package operate

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peios/peipkg-repo/internal/index"
	"github.com/peios/peipkg-repo/internal/state"
	"github.com/peios/peipkg-repo/internal/version"
)

// PublishConfig configures Publish.
type PublishConfig struct {
	// In is the previous state directory (output of Init or a prior
	// Publish). Required.
	In string

	// NewPackagesDir is a directory containing one or more .peipkg files
	// to add to the repository. May be empty (an empty publish bumps
	// index_version without changing package contents — useful for
	// re-signing after key rotation).
	NewPackagesDir string

	// SignKey signs the new descriptor and indexes. Required.
	SignKey ed25519.PrivateKey

	// Timestamp is the RFC 3339 UTC timestamp recorded as the new
	// indexes' generated_at, MUST end with 'Z'. Required.
	Timestamp string

	// Out is the directory the new state is written into. Required.
	// May equal In (publish-in-place) or be a fresh directory.
	Out string

	// PackageURLTemplate is the URL template for new entries. Supports
	// placeholders {name}, {version}, {arch}, {filename}. Empty defaults
	// to /p/{name}/{version}/{filename} (the §6.4 conventional path).
	//
	// The template applies only to NEW entries — already-published
	// entries keep their original URLs. This decouples publishing
	// infrastructure changes from historical-package URL stability.
	PackageURLTemplate string

	// Rebuild, when true, ignores the previous archive's package
	// entries and reconstructs them from scratch by re-hashing every
	// .peipkg in AllPackagesDir. Recovery path; default false.
	Rebuild bool

	// AllPackagesDir is required when Rebuild is true: a directory
	// containing every .peipkg the repository has ever published.
	// Ignored otherwise.
	AllPackagesDir string
}

// PublishReport summarises what one Publish call did.
type PublishReport struct {
	Added        []string // package filenames added to the archive
	IndexVersion int64    // new index_version
}

// Publish reads the previous state at cfg.In, ingests the .peipkg files
// at cfg.NewPackagesDir (or all of them at cfg.AllPackagesDir under
// --rebuild), produces fresh active and archive indexes with bumped
// index_version, signs them, and writes the new state to cfg.Out.
func Publish(cfg PublishConfig) (*PublishReport, error) {
	if err := validatePublish(cfg); err != nil {
		return nil, err
	}

	prev, err := state.Load(cfg.In)
	if err != nil {
		return nil, fmt.Errorf("load previous state: %w", err)
	}

	template := cfg.PackageURLTemplate
	if template == "" {
		template = defaultURLTemplate
	}

	report := &PublishReport{}

	// readAllPeipkgs returns paired (entry, sourcePath) slices so the
	// bytes can be copied into the output state once index assignment
	// is decided.
	var newEntries []index.Package
	var newSources []string
	if cfg.Rebuild {
		entries, sources, err := readAllPeipkgs(cfg.AllPackagesDir, template)
		if err != nil {
			return nil, err
		}
		newEntries = entries
		newSources = sources
		// In rebuild mode we discard the previous archive and rebuild from disk.
		prev.Archive.Packages = nil
	} else {
		entries, sources, err := readAllPeipkgs(cfg.NewPackagesDir, template)
		if err != nil {
			return nil, err
		}
		newEntries = entries
		newSources = sources
	}

	// Build the merged archive: previous archive entries plus new ones.
	// Reject re-publishing the same (name, version, architecture) — §6.3
	// retention guarantees historical entries are immutable.
	mergedArchive := append([]index.Package(nil), prev.Archive.Packages...)
	keyOf := func(p index.Package) string {
		return p.Name + "\x00" + p.Version + "\x00" + p.Architecture
	}
	existing := make(map[string]struct{}, len(mergedArchive))
	for _, p := range mergedArchive {
		existing[keyOf(p)] = struct{}{}
	}
	for _, p := range newEntries {
		k := keyOf(p)
		if _, dup := existing[k]; dup {
			return nil, fmt.Errorf("package %s_%s_%s already exists in the archive (§6.3 forbids re-publishing the same name+version+architecture)",
				p.Name, p.Version, p.Architecture)
		}
		existing[k] = struct{}{}
		mergedArchive = append(mergedArchive, p)
		report.Added = append(report.Added, fmt.Sprintf("%s_%s_%s.peipkg", p.Name, p.Version, p.Architecture))
	}

	if err := index.SortArchive(mergedArchive); err != nil {
		return nil, fmt.Errorf("sort archive: %w", err)
	}

	// Active = highest-version-per-name from the archive.
	active, err := deriveActive(mergedArchive)
	if err != nil {
		return nil, err
	}
	index.SortActive(active)

	// Bump index_version. Per §6.2.3 the new value must exceed every
	// previous value for the same repository — so we take the max of
	// both the old active and old archive index_version values.
	newIndexVersion := prev.Active.IndexVersion
	if prev.Archive.IndexVersion > newIndexVersion {
		newIndexVersion = prev.Archive.IndexVersion
	}
	newIndexVersion++
	report.IndexVersion = newIndexVersion

	repoName := prev.Descriptor.Repo.Name

	newActive := index.Index{
		SchemaVersion: index.SchemaVersion,
		Repo:          repoName,
		Kind:          index.KindActive,
		IndexVersion:  newIndexVersion,
		GeneratedAt:   cfg.Timestamp,
		Packages:      active,
	}
	newArchive := index.Index{
		SchemaVersion: index.SchemaVersion,
		Repo:          repoName,
		Kind:          index.KindArchive,
		IndexVersion:  newIndexVersion,
		GeneratedAt:   cfg.Timestamp,
		Packages:      mergedArchive,
	}

	if err := state.Save(cfg.Out, prev.Descriptor, newActive, newArchive, cfg.SignKey); err != nil {
		return nil, fmt.Errorf("save state: %w", err)
	}

	// Copy the new .peipkg bytes into the output state at the path
	// implied by each entry's URL. Entries whose URL is absolute
	// (http(s)://) are external — operator stores the bytes elsewhere
	// (GitHub Releases, S3 outside this repo, etc.) and we just record
	// the index entry pointing at it. Relative URLs (starting with "/")
	// are repo-rooted: bytes must live at <Out>/<URL> for a consumer
	// fetching <repo-base>/<URL> to find them.
	for i := range newEntries {
		if err := materialisePackage(cfg.Out, newEntries[i].URL, newSources[i]); err != nil {
			return nil, fmt.Errorf("materialise %s: %w", newSources[i], err)
		}
	}

	// Carry forward any public-key files from the previous state. Publish
	// does not change the trust set; whatever .pub files were in In/keys
	// must still be in Out/keys for the descriptor's signing.keys[].url
	// references to remain reachable.
	if cfg.In != cfg.Out {
		if err := copyKeysDir(cfg.In, cfg.Out); err != nil {
			return nil, fmt.Errorf("carry-forward keys directory: %w", err)
		}
	}

	// Carry forward already-published .peipkg files when In and Out are
	// distinct directories. Without this, an out-of-place publish loses
	// every previously-archived package's bytes (the index still
	// references them, but the files are only at In). In-place publish
	// (In == Out) preserves them automatically.
	if cfg.In != cfg.Out {
		if err := carryForwardPackages(cfg.In, cfg.Out, prev.Archive.Packages); err != nil {
			return nil, fmt.Errorf("carry-forward packages: %w", err)
		}
	}

	sort.Strings(report.Added)
	return report, nil
}

// copyKeysDir copies every file under <inDir>/keys/ into <outDir>/keys/.
// Used by Publish to preserve the trust set across state generations
// when In and Out are different directories.
func copyKeysDir(inDir, outDir string) error {
	srcKeys := filepath.Join(inDir, "keys")
	dstKeys := filepath.Join(outDir, "keys")

	entries, err := os.ReadDir(srcKeys)
	if err != nil {
		if os.IsNotExist(err) {
			// First publish into a fresh state with no keys/ in In —
			// shouldn't happen if Init produced In, but tolerate it.
			return nil
		}
		return err
	}
	if err := os.MkdirAll(dstKeys, 0o755); err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if err := copyFile(filepath.Join(srcKeys, e.Name()), filepath.Join(dstKeys, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

const defaultURLTemplate = "/p/{name}/{version}/{filename}"

func validatePublish(cfg PublishConfig) error {
	switch {
	case cfg.In == "":
		return fmt.Errorf("In is required")
	case cfg.SignKey == nil:
		return fmt.Errorf("SignKey is required")
	case cfg.Timestamp == "":
		return fmt.Errorf("Timestamp is required")
	case cfg.Out == "":
		return fmt.Errorf("Out is required")
	}
	if _, err := time.Parse(time.RFC3339, cfg.Timestamp); err != nil {
		return fmt.Errorf("Timestamp: %w", err)
	}
	if !strings.HasSuffix(cfg.Timestamp, "Z") {
		return fmt.Errorf("Timestamp must end with 'Z' for UTC (got %q)", cfg.Timestamp)
	}
	if cfg.Rebuild && cfg.AllPackagesDir == "" {
		return fmt.Errorf("--rebuild requires --all-packages-dir")
	}
	return nil
}

// readAllPeipkgs walks dir (non-recursively) for *.peipkg files, parses
// each, and returns one index.Package per file along with each file's
// source path so callers can copy the bytes after index assignment.
// Files whose names don't end in .peipkg are ignored.
func readAllPeipkgs(dir, urlTemplate string) ([]index.Package, []string, error) {
	if dir == "" {
		return nil, nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", dir, err)
	}

	var out []index.Package
	var sources []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".peipkg") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := readPeipkg(path)
		if err != nil {
			return nil, nil, err
		}

		filename := name
		entry := index.Package{
			Name:                 f.manifest.Name,
			Version:              f.manifest.Version,
			Architecture:         f.manifest.Architecture,
			Description:          f.manifest.Description,
			License:              f.manifest.License,
			Homepage:             f.manifest.Homepage,
			Dependencies:         f.manifest.Dependencies,
			OptionalDependencies: f.manifest.OptionalDependencies,
			Conflicts:            f.manifest.Conflicts,
			Provides:             f.manifest.Provides,
			Replaces:             f.manifest.Replaces,
			SideEffects:          f.manifest.SideEffects,
			SizeCompressed:       f.sizeCompressed,
			SizeInstalled:        f.manifest.SizeInstalled,
			Hash: index.Hash{
				Algorithm: index.HashAlgorithm,
				Value:     f.hashHex,
			},
			URL: renderURL(urlTemplate, f.manifest.Name, f.manifest.Version, f.manifest.Architecture, filename),
			Build: index.Build{
				Timestamp: f.manifest.Build.Timestamp,
				FarmID:    f.manifest.Build.FarmID,
			},
		}
		out = append(out, entry)
		sources = append(sources, path)
	}
	return out, sources, nil
}

// materialisePackage places a .peipkg's bytes into the output state at
// the path implied by entryURL. Absolute URLs (http(s)://) are external
// — bytes stay where the operator put them and this function no-ops.
// Relative URLs are repo-rooted: bytes are copied to <out>/<URL with
// leading slash trimmed>.
func materialisePackage(outDir, entryURL, sourcePath string) error {
	if strings.HasPrefix(entryURL, "http://") || strings.HasPrefix(entryURL, "https://") {
		return nil
	}
	rel := strings.TrimPrefix(entryURL, "/")
	if rel == "" {
		return fmt.Errorf("entry URL %q is empty after trimming leading slash", entryURL)
	}
	dst := filepath.Join(outDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return copyFile(sourcePath, dst)
}

// carryForwardPackages copies every .peipkg whose URL is repo-rooted
// from <inDir>/<URL> to <outDir>/<URL>. Used when In and Out are
// distinct so an out-of-place publish does not lose previously-archived
// package bytes. Already-existing destination files are left alone
// (cheap idempotency for repeated publishes that wrote partial state).
func carryForwardPackages(inDir, outDir string, archive []index.Package) error {
	for _, p := range archive {
		if strings.HasPrefix(p.URL, "http://") || strings.HasPrefix(p.URL, "https://") {
			continue
		}
		rel := strings.TrimPrefix(p.URL, "/")
		if rel == "" {
			continue
		}
		dst := filepath.Join(outDir, filepath.FromSlash(rel))
		if _, err := os.Stat(dst); err == nil {
			continue
		}
		src := filepath.Join(inDir, filepath.FromSlash(rel))
		if _, err := os.Stat(src); err != nil {
			if os.IsNotExist(err) {
				// Source missing too — nothing we can do; an earlier
				// publish under a buggy version may have skipped the
				// materialise step. Caller can recover via --rebuild.
				continue
			}
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := copyFile(src, dst); err != nil {
			return err
		}
	}
	return nil
}

// renderURL substitutes {name}, {version}, {arch}, {filename} into the
// template. Other text is passed through unmodified.
func renderURL(template, name, ver, arch, filename string) string {
	r := strings.NewReplacer(
		"{name}", name,
		"{version}", ver,
		"{arch}", arch,
		"{filename}", filename,
	)
	return r.Replace(template)
}

// deriveActive picks the highest-version package per name from a sorted
// archive (§6.3.5: archive is sorted name-asc, version-desc, so the
// first entry of each name group is the highest-version one).
//
// Returns an error if multiple highest-version entries share a name
// (the multi-architecture case). A v0.22 repository serves a single
// architecture; if the operator wants multi-arch, they need separate
// repositories per architecture.
func deriveActive(archive []index.Package) ([]index.Package, error) {
	if len(archive) == 0 {
		return nil, nil
	}
	out := make([]index.Package, 0, len(archive))
	seen := make(map[string]index.Package)
	maxVersion := make(map[string]version.Version)

	for _, p := range archive {
		v, err := version.Parse(p.Version)
		if err != nil {
			return nil, fmt.Errorf("package %s: parse version %q: %w", p.Name, p.Version, err)
		}
		prev, ok := seen[p.Name]
		if !ok {
			seen[p.Name] = p
			maxVersion[p.Name] = v
			continue
		}
		c := version.Compare(v, maxVersion[p.Name])
		switch {
		case c > 0:
			seen[p.Name] = p
			maxVersion[p.Name] = v
		case c < 0:
			// Older version — already have a newer; skip.
		case c == 0 && p.Architecture != prev.Architecture:
			return nil, fmt.Errorf("active index conflict: %s exists at version %s for both architectures %q and %q (§6.2.7 forbids duplicate names in the active index — split multi-arch packages across separate repositories)",
				p.Name, p.Version, prev.Architecture, p.Architecture)
		}
	}

	for _, p := range seen {
		out = append(out, p)
	}
	return out, nil
}

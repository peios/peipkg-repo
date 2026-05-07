package operate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/peios/peipkg-repo/internal/descriptor"
	"github.com/peios/peipkg-repo/internal/index"
	"github.com/peios/peipkg-repo/internal/signature"
	"github.com/peios/peipkg-repo/internal/state"
)

// VerifyMode selects which integrity checks Verify performs.
type VerifyMode int

const (
	// VerifyMetadata: schema, signatures, archive ⊇ active relationship,
	// per-name uniqueness in active. No file-content hashing. Sub-second
	// at any plausible repo scale; safe to run on every publish.
	VerifyMetadata VerifyMode = 1 << iota

	// VerifyHashes: re-hash each .peipkg file referenced by the indexes
	// and compare to the recorded hash. Disk-bound; run nightly or on
	// demand. Requires AllPackagesDir.
	VerifyHashes

	// VerifyAll runs metadata first (fail-fast) then hashes if metadata
	// passed.
	VerifyAll = VerifyMetadata | VerifyHashes
)

// VerifyConfig configures Verify.
type VerifyConfig struct {
	Repo string     // state directory to audit (required)
	Mode VerifyMode // bitmask; VerifyAll is the typical default

	// AllPackagesDir is required when Mode includes VerifyHashes:
	// directory containing every .peipkg referenced by the indexes.
	// Files are looked up by their filename
	// (<name>_<version>_<arch>.peipkg).
	AllPackagesDir string
}

// VerifyReport summarises a Verify call. Issues and Warnings are
// human-readable strings; OK is true iff Issues is empty.
type VerifyReport struct {
	Issues   []string
	Warnings []string
	OK       bool
}

// Verify runs the configured integrity checks and returns a report.
// Verify never modifies the repository state; it is read-only.
func Verify(cfg VerifyConfig) (*VerifyReport, error) {
	if cfg.Repo == "" {
		return nil, fmt.Errorf("Repo is required")
	}
	if cfg.Mode == 0 {
		return nil, fmt.Errorf("Mode is required (use VerifyMetadata, VerifyHashes, or VerifyAll)")
	}
	if cfg.Mode&VerifyHashes != 0 && cfg.AllPackagesDir == "" {
		return nil, fmt.Errorf("VerifyHashes requires AllPackagesDir")
	}

	loaded, err := state.Load(cfg.Repo)
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}

	report := &VerifyReport{}

	if cfg.Mode&VerifyMetadata != 0 {
		verifyMetadata(loaded, cfg.Repo, report)
		// If metadata failed and the caller asked for both, skip hashes
		// — there's no point hashing files when we can't trust the
		// index that names them.
		if cfg.Mode&VerifyHashes != 0 && len(report.Issues) > 0 {
			report.Warnings = append(report.Warnings, "skipping hash check because metadata check found issues")
			report.OK = false
			return report, nil
		}
	}

	if cfg.Mode&VerifyHashes != 0 {
		verifyHashes(loaded, cfg.AllPackagesDir, report)
	}

	report.OK = len(report.Issues) == 0
	return report, nil
}

// verifyMetadata checks signature envelopes, cryptographic signatures
// (against keys named in the descriptor), schema invariants, and the
// active ⊆ archive relationship.
func verifyMetadata(loaded *state.State, repoDir string, report *VerifyReport) {
	desc := loaded.Descriptor

	// Build a fingerprint → public-key index from the descriptor's keys
	// and the keys/ directory. We need the actual key bytes to verify
	// the signatures cryptographically — the descriptor only carries
	// fingerprints.
	pubKeys, keyIssues := loadDescriptorKeys(repoDir, desc)
	report.Issues = append(report.Issues, keyIssues...)

	// Each detached signature: present? envelope schema valid? key
	// fingerprint in the descriptor? cryptographic verify passes?
	verifySig := func(name string, body []byte, env *signature.Envelope) {
		if env == nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%s: no detached signature present (acceptable under §6.5.3 'optional' trust policy; rejected under 'required')", name))
			return
		}
		if env.SchemaVersion != signature.SchemaVersion {
			report.Issues = append(report.Issues, fmt.Sprintf("%s: signature schema_version %d (must be %d)", name, env.SchemaVersion, signature.SchemaVersion))
			return
		}
		if env.Algorithm != signature.Algorithm {
			report.Issues = append(report.Issues, fmt.Sprintf("%s: signature algorithm %q (v0.22 must be %q)", name, env.Algorithm, signature.Algorithm))
			return
		}
		pub, ok := pubKeys[env.KeyFingerprint]
		if !ok {
			report.Issues = append(report.Issues, fmt.Sprintf("%s: signing key fingerprint %s is not declared in the descriptor", name, env.KeyFingerprint))
			return
		}
		sigBytes, err := base64.RawStdEncoding.DecodeString(env.Signature)
		if err != nil {
			report.Issues = append(report.Issues, fmt.Sprintf("%s: signature value is not valid base64: %v", name, err))
			return
		}
		digest := sha256.Sum256(body)
		if !ed25519.Verify(pub, digest[:], sigBytes) {
			report.Issues = append(report.Issues, fmt.Sprintf("%s: signature does not verify against the declared key", name))
		}
	}

	verifySig("repo.json", loaded.DescriptorBytes, loaded.DescriptorSig)
	verifySig("active.json", loaded.ActiveBytes, loaded.ActiveSig)
	verifySig("archive.json", loaded.ArchiveBytes, loaded.ArchiveSig)

	// active ⊆ archive: every active entry has a matching archive
	// entry by (name, version, architecture, hash) per §6.3.5.
	archiveByKey := make(map[string]index.Package, len(loaded.Archive.Packages))
	for _, p := range loaded.Archive.Packages {
		archiveByKey[p.Name+"\x00"+p.Version+"\x00"+p.Architecture] = p
	}
	for _, a := range loaded.Active.Packages {
		k := a.Name + "\x00" + a.Version + "\x00" + a.Architecture
		ar, ok := archiveByKey[k]
		if !ok {
			report.Issues = append(report.Issues, fmt.Sprintf("active entry %s_%s_%s has no matching archive entry (§6.3.5)", a.Name, a.Version, a.Architecture))
			continue
		}
		if a.Hash.Value != ar.Hash.Value {
			report.Issues = append(report.Issues, fmt.Sprintf("active entry %s_%s_%s hash %s differs from archive entry hash %s",
				a.Name, a.Version, a.Architecture, a.Hash.Value, ar.Hash.Value))
		}
	}

	// Per-name uniqueness in active (§6.2.7).
	activeNames := make(map[string]struct{}, len(loaded.Active.Packages))
	for _, p := range loaded.Active.Packages {
		if _, dup := activeNames[p.Name]; dup {
			report.Issues = append(report.Issues, fmt.Sprintf("active index has duplicate name %q (§6.2.7)", p.Name))
			continue
		}
		activeNames[p.Name] = struct{}{}
	}

	// Index-version sanity: the spec mandates monotonic-positive but we
	// can at least flag obviously-broken values here.
	if loaded.Active.IndexVersion < 1 {
		report.Issues = append(report.Issues, fmt.Sprintf("active.index_version is %d (must be >= 1)", loaded.Active.IndexVersion))
	}
	if loaded.Archive.IndexVersion < 1 {
		report.Issues = append(report.Issues, fmt.Sprintf("archive.index_version is %d (must be >= 1)", loaded.Archive.IndexVersion))
	}
}

// loadDescriptorKeys reads keys/<fingerprint>.pub for each key in
// descriptor.Repo.Signing.Keys and returns a fingerprint→key map.
// Issues for missing or unreadable keys are returned for the caller to
// merge into its report.
func loadDescriptorKeys(repoDir string, desc descriptor.Descriptor) (map[string]ed25519.PublicKey, []string) {
	out := make(map[string]ed25519.PublicKey, len(desc.Repo.Signing.Keys))
	var issues []string
	for _, k := range desc.Repo.Signing.Keys {
		if k.Status == descriptor.StatusRevoked {
			// Revoked keys are not used to verify anything; skip.
			continue
		}
		path := filepath.Join(repoDir, "keys", k.Fingerprint+".pub")
		data, err := os.ReadFile(path)
		if err != nil {
			issues = append(issues, fmt.Sprintf("descriptor key %s: read %s: %v", k.Fingerprint, path, err))
			continue
		}
		pub, err := signature.ParsePublicKey(data)
		if err != nil {
			issues = append(issues, fmt.Sprintf("descriptor key %s: parse: %v", k.Fingerprint, err))
			continue
		}
		// Sanity: the file's contents should fingerprint to the declared value.
		if got := signature.Fingerprint(pub); got != k.Fingerprint {
			issues = append(issues, fmt.Sprintf("key file %s.pub fingerprints to %s (declared %s)", k.Fingerprint, got, k.Fingerprint))
			continue
		}
		out[k.Fingerprint] = pub
	}
	return out, issues
}

// verifyHashes re-hashes every .peipkg referenced by either index and
// compares to the recorded hash. Files are looked up in pkgsDir by their
// expected filename: <name>_<version>_<arch>.peipkg.
func verifyHashes(loaded *state.State, pkgsDir string, report *VerifyReport) {
	// Deduplicate by filename — many archive entries also appear in
	// active, no need to hash twice.
	seen := make(map[string]index.Hash)
	for _, p := range loaded.Active.Packages {
		seen[fileNameOf(p)] = p.Hash
	}
	for _, p := range loaded.Archive.Packages {
		seen[fileNameOf(p)] = p.Hash
	}

	files := make([]string, 0, len(seen))
	for f := range seen {
		files = append(files, f)
	}
	sort.Strings(files)

	for _, fname := range files {
		path := filepath.Join(pkgsDir, fname)
		data, err := os.ReadFile(path)
		if err != nil {
			report.Issues = append(report.Issues, fmt.Sprintf("hash check: read %s: %v", fname, err))
			continue
		}
		got := sha256.Sum256(data)
		want := seen[fname].Value
		gotHex := hashHex(got[:])
		if gotHex != want {
			report.Issues = append(report.Issues, fmt.Sprintf("hash mismatch: %s computed %s, index claimed %s", fname, gotHex, want))
		}
	}
}

func fileNameOf(p index.Package) string {
	return fmt.Sprintf("%s_%s_%s.peipkg", p.Name, p.Version, p.Architecture)
}

func hashHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hex[x>>4]
		out[i*2+1] = hex[x&0x0f]
	}
	return string(out)
}

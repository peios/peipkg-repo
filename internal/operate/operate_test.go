package operate

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/peios/peipkg-repo/internal/signature"
	"github.com/peios/peipkg-repo/internal/state"
	"github.com/peios/peipkg-repo/web"
)

// makeTestKey returns a deterministic Ed25519 key pair for tests.
func makeTestKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0xa0 ^ i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

// makeTestPeipkg constructs an in-memory .peipkg that contains exactly
// what peipkg-repo needs to read: a manifest entry and a files entry.
// No payload, no signature. Real peipkgs (from peipkg-build) work too;
// this helper exists so peipkg-repo's tests don't depend on the sibling
// build tool's output format details.
func makeTestPeipkg(t *testing.T, name, version, arch string) []byte {
	t.Helper()

	manifest := map[string]any{
		"schema_version":        1,
		"name":                  name,
		"version":               version,
		"architecture":          arch,
		"description":           "",
		"license":               "",
		"homepage":              "",
		"dependencies":          []any{},
		"optional_dependencies": []any{},
		"conflicts":             []any{},
		"provides":              []any{},
		"replaces":              []any{},
		"side_effects":          []any{},
		"size_installed":        0,
		"sd_overrides":          []any{},
		"build": map[string]any{
			"timestamp":  "2026-05-07T00:00:00Z",
			"farm_id":    "test-farm",
			"source_ref": "test://" + name,
		},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	filesManifest := map[string]any{
		"schema_version": 1,
		"algorithm":      "sha256",
		"entries":        []any{},
	}
	filesJSON, err := json.Marshal(filesManifest)
	if err != nil {
		t.Fatal(err)
	}

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, entry := range []struct {
		path string
		body []byte
	}{
		{".peipkg/manifest.json", manifestJSON},
		{".peipkg/files.json", filesJSON},
	} {
		hdr := &tar.Header{
			Name:     entry.path,
			Mode:     0o777,
			Size:     int64(len(entry.body)),
			Uid:      0,
			Gid:      0,
			Uname:    "root",
			Gname:    "root",
			Format:   tar.FormatPAX,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	var compressed bytes.Buffer
	zw, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

// writeTestPeipkg writes a generated peipkg to a directory under its
// canonical filename.
func writeTestPeipkg(t *testing.T, dir, name, version, arch string) string {
	t.Helper()
	bs := makeTestPeipkg(t, name, version, arch)
	filename := name + "_" + version + "_" + arch + ".peipkg"
	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, bs, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInitProducesSignedReadableState(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "state")
	priv, pub := makeTestKey(t)

	keyPath := filepath.Join(dir, "key.bin")
	if err := os.WriteFile(keyPath, priv.Seed(), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Init(InitConfig{
		Name:        "test-repo",
		Description: "for tests",
		SignKey:     priv,
		Timestamp:   "2026-05-07T00:00:00Z",
		Out:         out,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	loaded, err := state.Load(out)
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if loaded.Descriptor.Repo.Name != "test-repo" {
		t.Errorf("repo name = %q", loaded.Descriptor.Repo.Name)
	}
	if loaded.Active.IndexVersion != 1 {
		t.Errorf("active index_version = %d, want 1", loaded.Active.IndexVersion)
	}
	if len(loaded.Active.Packages) != 0 {
		t.Errorf("fresh active should be empty, got %d packages", len(loaded.Active.Packages))
	}

	// Descriptor signature verifies against the signing key.
	if loaded.DescriptorSig == nil {
		t.Fatal("descriptor signature missing")
	}
	sigBytes, err := base64.RawStdEncoding.DecodeString(loaded.DescriptorSig.Signature)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(loaded.DescriptorBytes)
	if !ed25519.Verify(pub, digest[:], sigBytes) {
		t.Error("descriptor signature does not verify")
	}
}

func TestInitRefusesNonEmptyDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stray"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	priv, _ := makeTestKey(t)
	err := Init(InitConfig{
		Name:      "x",
		SignKey:   priv,
		Timestamp: "2026-05-07T00:00:00Z",
		Out:       dir,
	})
	if err == nil {
		t.Error("Init should refuse to overwrite non-empty directory")
	}
}

func TestPublishHappyPath(t *testing.T) {
	dir := t.TempDir()
	state1 := filepath.Join(dir, "state1")
	state2 := filepath.Join(dir, "state2")
	pkgs := filepath.Join(dir, "pkgs")
	if err := os.MkdirAll(pkgs, 0o755); err != nil {
		t.Fatal(err)
	}
	priv, _ := makeTestKey(t)

	if err := Init(InitConfig{
		Name: "rt", SignKey: priv,
		Timestamp: "2026-05-07T00:00:00Z", Out: state1,
	}); err != nil {
		t.Fatal(err)
	}

	writeTestPeipkg(t, pkgs, "alpha", "1.0-1", "noarch")
	writeTestPeipkg(t, pkgs, "beta", "0.5-1", "x86_64")

	report, err := Publish(PublishConfig{
		In:             state1,
		NewPackagesDir: pkgs,
		SignKey:        priv,
		Timestamp:      "2026-05-07T01:00:00Z",
		Out:            state2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.IndexVersion != 2 {
		t.Errorf("IndexVersion = %d, want 2", report.IndexVersion)
	}
	if len(report.Added) != 2 {
		t.Errorf("Added = %v", report.Added)
	}

	loaded, err := state.Load(state2)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Active.Packages) != 2 {
		t.Errorf("active has %d packages, want 2", len(loaded.Active.Packages))
	}
	if len(loaded.Archive.Packages) != 2 {
		t.Errorf("archive has %d packages, want 2", len(loaded.Archive.Packages))
	}

	// Verify both modes pass.
	rep, err := Verify(VerifyConfig{
		Repo:           state2,
		Mode:           VerifyAll,
		AllPackagesDir: pkgs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Errorf("Verify failed:\n  issues: %v\n  warnings: %v", rep.Issues, rep.Warnings)
	}
}

// TestPublishMaterialisesPackageBytes guards against the regression
// where index entries pointed at /p/<name>/<version>/<filename> but
// the actual .peipkg bytes were never copied into the output state —
// the index claimed packages that were missing on disk, breaking
// rclone-sync uploads and direct hash verification.
func TestPublishMaterialisesPackageBytes(t *testing.T) {
	dir := t.TempDir()
	state1 := filepath.Join(dir, "state1")
	state2 := filepath.Join(dir, "state2")
	pkgs := filepath.Join(dir, "pkgs")
	if err := os.MkdirAll(pkgs, 0o755); err != nil {
		t.Fatal(err)
	}
	priv, _ := makeTestKey(t)

	if err := Init(InitConfig{
		Name: "rt", SignKey: priv,
		Timestamp: "2026-05-07T00:00:00Z", Out: state1,
	}); err != nil {
		t.Fatal(err)
	}

	writeTestPeipkg(t, pkgs, "alpha", "1.0-1", "noarch")
	writeTestPeipkg(t, pkgs, "beta", "0.5-1", "x86_64")

	if _, err := Publish(PublishConfig{
		In:             state1,
		NewPackagesDir: pkgs,
		SignKey:        priv,
		Timestamp:      "2026-05-07T01:00:00Z",
		Out:            state2,
	}); err != nil {
		t.Fatal(err)
	}

	loaded, err := state.Load(state2)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range loaded.Archive.Packages {
		// The index entry's URL is repo-rooted; the bytes must live at
		// state2/<URL with leading slash trimmed>.
		want := filepath.Join(state2, strings.TrimPrefix(p.URL, "/"))
		if _, err := os.Stat(want); err != nil {
			t.Errorf("package %s_%s: bytes missing at %s: %v", p.Name, p.Version, want, err)
		}
	}
}

// TestPublishOutOfPlaceCarriesForwardArchiveBytes guards against an
// out-of-place publish dropping previously-archived package bytes:
// each generation of state must carry every archived .peipkg forward
// so historical packages remain fetchable from the new state.
func TestPublishOutOfPlaceCarriesForwardArchiveBytes(t *testing.T) {
	dir := t.TempDir()
	state1 := filepath.Join(dir, "state1")
	state2 := filepath.Join(dir, "state2")
	state3 := filepath.Join(dir, "state3")
	priv, _ := makeTestKey(t)

	if err := Init(InitConfig{
		Name: "rt", SignKey: priv,
		Timestamp: "2026-05-07T00:00:00Z", Out: state1,
	}); err != nil {
		t.Fatal(err)
	}

	// First publish: alpha 1.0.
	pkgs1 := filepath.Join(dir, "pkgs1")
	os.MkdirAll(pkgs1, 0o755)
	writeTestPeipkg(t, pkgs1, "alpha", "1.0-1", "noarch")
	if _, err := Publish(PublishConfig{
		In:             state1,
		NewPackagesDir: pkgs1,
		SignKey:        priv,
		Timestamp:      "2026-05-07T01:00:00Z",
		Out:            state2,
	}); err != nil {
		t.Fatal(err)
	}

	// Second publish: alpha 2.0. state3 must contain BOTH versions'
	// bytes — 1.0 from the previous archive (carry-forward) plus the
	// new 2.0 (materialise).
	pkgs2 := filepath.Join(dir, "pkgs2")
	os.MkdirAll(pkgs2, 0o755)
	writeTestPeipkg(t, pkgs2, "alpha", "2.0-1", "noarch")
	if _, err := Publish(PublishConfig{
		In:             state2,
		NewPackagesDir: pkgs2,
		SignKey:        priv,
		Timestamp:      "2026-05-07T02:00:00Z",
		Out:            state3,
	}); err != nil {
		t.Fatal(err)
	}

	loaded, err := state.Load(state3)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Archive.Packages) != 2 {
		t.Fatalf("expected 2 archived packages in state3, got %d", len(loaded.Archive.Packages))
	}
	for _, p := range loaded.Archive.Packages {
		want := filepath.Join(state3, strings.TrimPrefix(p.URL, "/"))
		if _, err := os.Stat(want); err != nil {
			t.Errorf("package %s_%s: bytes missing at %s: %v", p.Name, p.Version, want, err)
		}
	}
}

func TestPublishIncrementalKeepsArchive(t *testing.T) {
	dir := t.TempDir()
	state1 := filepath.Join(dir, "state1")
	state2 := filepath.Join(dir, "state2")
	state3 := filepath.Join(dir, "state3")
	priv, _ := makeTestKey(t)

	if err := Init(InitConfig{
		Name: "rt", SignKey: priv,
		Timestamp: "2026-05-07T00:00:00Z", Out: state1,
	}); err != nil {
		t.Fatal(err)
	}

	pkgs1 := filepath.Join(dir, "pkgs1")
	os.MkdirAll(pkgs1, 0o755)
	writeTestPeipkg(t, pkgs1, "alpha", "1.0-1", "noarch")

	pkgs2 := filepath.Join(dir, "pkgs2")
	os.MkdirAll(pkgs2, 0o755)
	writeTestPeipkg(t, pkgs2, "alpha", "1.1-1", "noarch")
	writeTestPeipkg(t, pkgs2, "beta", "0.5-1", "noarch")

	if _, err := Publish(PublishConfig{
		In: state1, NewPackagesDir: pkgs1, SignKey: priv,
		Timestamp: "2026-05-07T01:00:00Z", Out: state2,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(PublishConfig{
		In: state2, NewPackagesDir: pkgs2, SignKey: priv,
		Timestamp: "2026-05-07T02:00:00Z", Out: state3,
	}); err != nil {
		t.Fatal(err)
	}

	loaded, err := state.Load(state3)
	if err != nil {
		t.Fatal(err)
	}

	// Active: alpha at 1.1 (newer wins), beta at 0.5.
	activeMap := map[string]string{}
	for _, p := range loaded.Active.Packages {
		activeMap[p.Name] = p.Version
	}
	if activeMap["alpha"] != "1.1-1" {
		t.Errorf("active alpha version = %q, want 1.1-1", activeMap["alpha"])
	}
	if activeMap["beta"] != "0.5-1" {
		t.Errorf("active beta version = %q, want 0.5-1", activeMap["beta"])
	}

	// Archive: alpha 1.0-1 retained alongside alpha 1.1-1.
	archiveCount := 0
	hasOldAlpha := false
	for _, p := range loaded.Archive.Packages {
		archiveCount++
		if p.Name == "alpha" && p.Version == "1.0-1" {
			hasOldAlpha = true
		}
	}
	if archiveCount != 3 {
		t.Errorf("archive has %d entries, want 3 (alpha 1.0, alpha 1.1, beta 0.5)", archiveCount)
	}
	if !hasOldAlpha {
		t.Error("archive missing the superseded alpha 1.0-1 (§6.3 retention)")
	}

	// Archive sort: alpha entries first (lex), with 1.1 before 1.0
	// (descending within name).
	pkgs := loaded.Archive.Packages
	if pkgs[0].Name != "alpha" || pkgs[0].Version != "1.1-1" {
		t.Errorf("archive[0] = %s/%s, want alpha/1.1-1", pkgs[0].Name, pkgs[0].Version)
	}
	if pkgs[1].Name != "alpha" || pkgs[1].Version != "1.0-1" {
		t.Errorf("archive[1] = %s/%s, want alpha/1.0-1", pkgs[1].Name, pkgs[1].Version)
	}
	if pkgs[2].Name != "beta" {
		t.Errorf("archive[2].Name = %q, want beta", pkgs[2].Name)
	}
}

func TestPublishRejectsRepublish(t *testing.T) {
	dir := t.TempDir()
	state1 := filepath.Join(dir, "state1")
	state2 := filepath.Join(dir, "state2")
	priv, _ := makeTestKey(t)
	pkgs := filepath.Join(dir, "pkgs")
	os.MkdirAll(pkgs, 0o755)
	writeTestPeipkg(t, pkgs, "alpha", "1.0-1", "noarch")

	if err := Init(InitConfig{
		Name: "rt", SignKey: priv,
		Timestamp: "2026-05-07T00:00:00Z", Out: state1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(PublishConfig{
		In: state1, NewPackagesDir: pkgs, SignKey: priv,
		Timestamp: "2026-05-07T01:00:00Z", Out: state2,
	}); err != nil {
		t.Fatal(err)
	}

	_, err := Publish(PublishConfig{
		In: state2, NewPackagesDir: pkgs, SignKey: priv,
		Timestamp: "2026-05-07T02:00:00Z", Out: filepath.Join(dir, "stateX"),
	})
	if err == nil {
		t.Error("Publish should reject re-publishing the same package version")
	}
}

func TestPublishDeterministic(t *testing.T) {
	dir := t.TempDir()
	state1 := filepath.Join(dir, "state1")
	pkgs := filepath.Join(dir, "pkgs")
	os.MkdirAll(pkgs, 0o755)
	priv, _ := makeTestKey(t)
	writeTestPeipkg(t, pkgs, "alpha", "1.0-1", "noarch")
	writeTestPeipkg(t, pkgs, "beta", "0.5-1", "x86_64")

	if err := Init(InitConfig{
		Name: "det", SignKey: priv,
		Timestamp: "2026-05-07T00:00:00Z", Out: state1,
	}); err != nil {
		t.Fatal(err)
	}

	publishOnce := func(out string) {
		if _, err := Publish(PublishConfig{
			In: state1, NewPackagesDir: pkgs, SignKey: priv,
			Timestamp: "2026-05-07T01:00:00Z", Out: out,
		}); err != nil {
			t.Fatal(err)
		}
	}

	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	publishOnce(a)
	publishOnce(b)

	for _, path := range []string{
		"repo.json", "repo.json.sig",
		filepath.Join("index", "active.json"),
		filepath.Join("index", "active.json.sig"),
		filepath.Join("index", "archive.json"),
		filepath.Join("index", "archive.json.sig"),
	} {
		ax, err := os.ReadFile(filepath.Join(a, path))
		if err != nil {
			t.Fatal(err)
		}
		bx, err := os.ReadFile(filepath.Join(b, path))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ax, bx) {
			t.Errorf("%s: not byte-deterministic", path)
		}
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	dir := t.TempDir()
	state1 := filepath.Join(dir, "state1")
	state2 := filepath.Join(dir, "state2")
	pkgs := filepath.Join(dir, "pkgs")
	os.MkdirAll(pkgs, 0o755)
	priv, _ := makeTestKey(t)

	if err := Init(InitConfig{
		Name: "rt", SignKey: priv,
		Timestamp: "2026-05-07T00:00:00Z", Out: state1,
	}); err != nil {
		t.Fatal(err)
	}
	pkgPath := writeTestPeipkg(t, pkgs, "alpha", "1.0-1", "noarch")
	if _, err := Publish(PublishConfig{
		In: state1, NewPackagesDir: pkgs, SignKey: priv,
		Timestamp: "2026-05-07T01:00:00Z", Out: state2,
	}); err != nil {
		t.Fatal(err)
	}

	// Append junk to the .peipkg.
	if err := os.WriteFile(pkgPath, append([]byte("EXTRA"), readFile(t, pkgPath)...), 0o644); err != nil {
		t.Fatal(err)
	}

	rep, err := Verify(VerifyConfig{Repo: state2, Mode: VerifyHashes, AllPackagesDir: pkgs})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Error("Verify(--mode hashes) should detect the tampered package")
	}
	if len(rep.Issues) == 0 {
		t.Error("expected at least one issue describing the hash mismatch")
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPublishMaterialisesSiteAndSidecars asserts that a publish writes
// the embedded browse site to the repo root and extracts each package's
// manifest.json and files.json next to its .peipkg — the inputs the
// package-search website reads at runtime.
func TestPublishMaterialisesSiteAndSidecars(t *testing.T) {
	dir := t.TempDir()
	state1 := filepath.Join(dir, "state1")
	state2 := filepath.Join(dir, "state2")
	pkgs := filepath.Join(dir, "pkgs")
	if err := os.MkdirAll(pkgs, 0o755); err != nil {
		t.Fatal(err)
	}
	priv, _ := makeTestKey(t)

	if err := Init(InitConfig{
		Name: "rt", SignKey: priv,
		Timestamp: "2026-05-07T00:00:00Z", Out: state1,
	}); err != nil {
		t.Fatal(err)
	}
	writeTestPeipkg(t, pkgs, "alpha", "1.0-1", "noarch")

	if _, err := Publish(PublishConfig{
		In: state1, NewPackagesDir: pkgs, SignKey: priv,
		Timestamp: "2026-05-07T01:00:00Z", Out: state2,
	}); err != nil {
		t.Fatal(err)
	}

	// Browse site materialised at the repo root, byte-identical to the
	// embedded copy.
	wantIndex, err := web.FS.ReadFile("index.html")
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(state2, "index.html")); !bytes.Equal(got, wantIndex) {
		t.Error("materialised index.html does not match the embedded site")
	}
	for _, asset := range []string{"assets/style.css", "assets/app.js"} {
		if _, err := os.Stat(filepath.Join(state2, filepath.FromSlash(asset))); err != nil {
			t.Errorf("missing site asset %s: %v", asset, err)
		}
	}

	// Per-package sidecars are the package's own verbatim metadata,
	// including the source_ref and sd_overrides the index omits.
	pkgDir := filepath.Join(state2, "p", "alpha", "1.0-1")
	manifest := readFile(t, filepath.Join(pkgDir, "manifest.json"))
	if !bytes.Contains(manifest, []byte(`"source_ref":"test://alpha"`)) {
		t.Errorf("manifest sidecar missing source_ref; got: %s", manifest)
	}
	if !bytes.Contains(manifest, []byte(`"sd_overrides"`)) {
		t.Errorf("manifest sidecar missing sd_overrides; got: %s", manifest)
	}
	if files := readFile(t, filepath.Join(pkgDir, "files.json")); !bytes.Contains(files, []byte(`"algorithm":"sha256"`)) {
		t.Errorf("files.json sidecar malformed; got: %s", files)
	}

	// Site/sidecars are outside the signed set and must not break
	// integrity verification.
	rep, err := Verify(VerifyConfig{Repo: state2, Mode: VerifyAll, AllPackagesDir: pkgs})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Errorf("Verify failed after site/sidecar materialise: %v", rep.Issues)
	}
}

// TestPublishBackfillsSidecarsForExistingPackages proves the sidecar
// pass runs over the whole archive, so the first publish after upgrading
// peipkg-repo backfills packages that predate sidecar support.
func TestPublishBackfillsSidecarsForExistingPackages(t *testing.T) {
	dir := t.TempDir()
	state1 := filepath.Join(dir, "state1")
	state2 := filepath.Join(dir, "state2")
	pkgs := filepath.Join(dir, "pkgs")
	if err := os.MkdirAll(pkgs, 0o755); err != nil {
		t.Fatal(err)
	}
	priv, _ := makeTestKey(t)

	if err := Init(InitConfig{
		Name: "rt", SignKey: priv,
		Timestamp: "2026-05-07T00:00:00Z", Out: state1,
	}); err != nil {
		t.Fatal(err)
	}
	writeTestPeipkg(t, pkgs, "alpha", "1.0-1", "noarch")
	if _, err := Publish(PublishConfig{
		In: state1, NewPackagesDir: pkgs, SignKey: priv,
		Timestamp: "2026-05-07T01:00:00Z", Out: state2,
	}); err != nil {
		t.Fatal(err)
	}

	// Simulate state produced before sidecar support: drop the sidecars
	// but keep the archived .peipkg bytes.
	pkgDir := filepath.Join(state2, "p", "alpha", "1.0-1")
	if err := os.Remove(filepath.Join(pkgDir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(pkgDir, "files.json")); err != nil {
		t.Fatal(err)
	}

	// An empty in-place publish must regenerate them from the archived
	// package bytes.
	empty := filepath.Join(dir, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(PublishConfig{
		In: state2, NewPackagesDir: empty, SignKey: priv,
		Timestamp: "2026-05-07T02:00:00Z", Out: state2,
	}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"manifest.json", "files.json"} {
		if _, err := os.Stat(filepath.Join(pkgDir, s)); err != nil {
			t.Errorf("backfill did not recreate %s: %v", s, err)
		}
	}
}

// TestEndToEndAgainstRealPeipkgBuild is a bigger integration test that
// uses peipkg-build's real fixtures (when available) instead of our
// in-process generator. Skipped if peipkg-build's testdata isn't
// reachable.
func TestEndToEndAgainstRealPeipkgBuild(t *testing.T) {
	// Skip if not run from the peios/ tree.
	siblingFixtures := filepath.Join("..", "..", "..", "peipkg-build", "testdata", "cases", "hello-noarch", "expected", "hello_0.1-1_noarch.peipkg")
	if _, err := os.Stat(siblingFixtures); err != nil {
		t.Skipf("peipkg-build fixtures not found at %s; skipping cross-project test", siblingFixtures)
	}
	dir := t.TempDir()
	pkgs := filepath.Join(dir, "pkgs")
	os.MkdirAll(pkgs, 0o755)

	// Copy the real .peipkg into the fresh pkgs dir.
	src, err := os.ReadFile(siblingFixtures)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgs, "hello_0.1-1_noarch.peipkg"), src, 0o644); err != nil {
		t.Fatal(err)
	}

	priv, pub := makeTestKey(t)
	state1 := filepath.Join(dir, "state1")
	state2 := filepath.Join(dir, "state2")
	if err := Init(InitConfig{
		Name: "real-fixture", SignKey: priv,
		Timestamp: "2026-05-07T00:00:00Z", Out: state1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(PublishConfig{
		In: state1, NewPackagesDir: pkgs, SignKey: priv,
		Timestamp: "2026-05-07T01:00:00Z", Out: state2,
	}); err != nil {
		t.Fatal(err)
	}

	loaded, err := state.Load(state2)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Active.Packages) != 1 {
		t.Fatalf("active has %d packages, want 1", len(loaded.Active.Packages))
	}
	p := loaded.Active.Packages[0]
	if p.Name != "hello" {
		t.Errorf("name = %q, want hello", p.Name)
	}
	wantHash := sha256.Sum256(src)
	if p.Hash.Value != hex.EncodeToString(wantHash[:]) {
		t.Errorf("hash mismatch (computed %s vs index %s)",
			hex.EncodeToString(wantHash[:]), p.Hash.Value)
	}

	// Verify all three checks.
	rep, err := Verify(VerifyConfig{Repo: state2, Mode: VerifyAll, AllPackagesDir: pkgs})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Errorf("Verify failed: %v", rep.Issues)
	}

	// And confirm fingerprint matches the signing key.
	expectedFP := signature.Fingerprint(pub)
	if loaded.Descriptor.Repo.Signing.Keys[0].Fingerprint != expectedFP {
		t.Errorf("descriptor key fingerprint mismatch")
	}
}

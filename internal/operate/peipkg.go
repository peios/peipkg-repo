package operate

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"

	"github.com/peios/peipkg-repo/internal/index"
)

// peipkgManifest mirrors the subset of PSD-009 §3.3 manifest fields that
// the index entry consumes (§6.2.4). Fields we don't need on the index
// (sd_overrides, build.source_ref, schema_version) are intentionally
// omitted — encoding/json silently drops unknown JSON fields when
// unmarshalling, so the manifest's full bytes round-trip through this
// type's narrower view without error.
type peipkgManifest struct {
	Name                 string             `json:"name"`
	Version              string             `json:"version"`
	Architecture         string             `json:"architecture"`
	Description          string             `json:"description"`
	License              string             `json:"license"`
	Homepage             string             `json:"homepage"`
	Dependencies         []index.Dependency `json:"dependencies"`
	OptionalDependencies []index.Dependency `json:"optional_dependencies"`
	Conflicts            []index.Dependency `json:"conflicts"`
	Provides             []index.Provides   `json:"provides"`
	Replaces             []index.Replaces   `json:"replaces"`
	SideEffects          []string           `json:"side_effects"`
	SizeInstalled        int64              `json:"size_installed"`
	Build                struct {
		Timestamp string `json:"timestamp"`
		FarmID    string `json:"farm_id"`
	} `json:"build"`
}

// peipkgFile is the data peipkg-repo needs from a single .peipkg file
// to construct its index entry: the parsed manifest plus the SHA-256
// hash and compressed size of the file as a whole.
//
// manifestRaw and filesRaw hold the verbatim bytes of the package's own
// .peipkg/manifest.json and .peipkg/files.json entries, written out
// unchanged as repository sidecars so the browse site can render full
// metadata and the installed-file listing without decompressing the
// package. filesRaw is nil when the package omits files.json.
type peipkgFile struct {
	manifest       peipkgManifest
	manifestRaw    []byte
	filesRaw       []byte
	hashHex        string
	sizeCompressed int64
}

// readPeipkg opens path, computes SHA-256 over its compressed bytes, and
// extracts the manifest from inside the zstd-compressed tar archive.
//
// The compressed bytes are read into memory because we need both the
// hash (over compressed bytes) AND the manifest content (inside
// decompressed tar). Reading once into a buffer is simpler and bounded
// by .peipkg file size — which §3.5.4 caps at ~4 GiB even for malicious
// inputs and is typically a few MB for well-formed packages.
func readPeipkg(path string) (peipkgFile, error) {
	var f peipkgFile

	data, err := os.ReadFile(path)
	if err != nil {
		return f, fmt.Errorf("read %s: %w", path, err)
	}
	f.sizeCompressed = int64(len(data))

	sum := sha256.Sum256(data)
	f.hashHex = hex.EncodeToString(sum[:])

	zr, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return f, fmt.Errorf("zstd reader for %s: %w", path, err)
	}
	defer zr.Close()

	// §3.2 orders the metadata entries manifest.json then files.json
	// ahead of the payload, so we can stop as soon as both are in hand
	// rather than decompressing the whole archive (the payload may be
	// hundreds of MiB).
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return f, fmt.Errorf("%s: tar walk: %w", path, err)
		}
		switch h.Name {
		case ".peipkg/manifest.json":
			body, err := io.ReadAll(tr)
			if err != nil {
				return f, fmt.Errorf("%s: read manifest body: %w", path, err)
			}
			f.manifestRaw = body
			if err := json.Unmarshal(body, &f.manifest); err != nil {
				return f, fmt.Errorf("%s: parse manifest: %w", path, err)
			}
		case ".peipkg/files.json":
			body, err := io.ReadAll(tr)
			if err != nil {
				return f, fmt.Errorf("%s: read files.json body: %w", path, err)
			}
			f.filesRaw = body
		}
		if f.manifestRaw != nil && f.filesRaw != nil {
			break
		}
	}
	if f.manifestRaw == nil {
		return f, fmt.Errorf("%s: no .peipkg/manifest.json entry found", path)
	}
	return f, nil
}

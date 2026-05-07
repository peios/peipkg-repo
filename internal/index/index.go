// Package index defines the on-wire schema and canonical encoding for
// the active and archive indexes (PSD-009 §6.2 and §6.3).
//
// The two indexes share a top-level schema and a per-package entry
// schema; only the `kind` field and the sort order differ. We model that
// with a single Index type plus separate sort helpers.
package index

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/peios/peipkg-repo/internal/version"
)

// SchemaVersion is the index schema version this package emits.
const SchemaVersion = 1

// HashAlgorithm is the hash-algorithm identifier this package emits and
// accepts. PSD-009 v0.22 supports SHA-256 only (§6.2.5).
const HashAlgorithm = "sha256"

// Kind values per §6.2.2 and §6.3.3.
const (
	KindActive  = "active"
	KindArchive = "archive"
)

// Index is the document at <repo-base>/index/active.json (Kind=KindActive)
// or <repo-base>/index/archive.json (Kind=KindArchive). The two share a
// schema; only Kind, sort discipline (see SortActive / SortArchive), and
// the per-name uniqueness rule differ.
type Index struct {
	SchemaVersion int       `json:"schema_version"`
	Repo          string    `json:"repo"`
	Kind          string    `json:"kind"`
	IndexVersion  int64     `json:"index_version"`
	GeneratedAt   string    `json:"generated_at"`
	Packages      []Package `json:"packages"`
}

// Package is one entry in the index's `packages` array. Field declaration
// order is the on-wire byte order — do not reorder without amending §6.2.4.
//
// Required fields per §6.2.4: Name, Version, Architecture, Dependencies,
// Conflicts, SizeCompressed, SizeInstalled, Hash, URL. The other fields
// are RECOMMENDED but optional. We always emit them for byte-stability;
// optional string fields default to empty string and optional array
// fields default to empty array.
type Package struct {
	Name                 string       `json:"name"`
	Version              string       `json:"version"`
	Architecture         string       `json:"architecture"`
	Description          string       `json:"description"`
	License              string       `json:"license"`
	Homepage             string       `json:"homepage"`
	Dependencies         []Dependency `json:"dependencies"`
	OptionalDependencies []Dependency `json:"optional_dependencies"`
	Conflicts            []Dependency `json:"conflicts"`
	Provides             []Provides   `json:"provides"`
	Replaces             []Replaces   `json:"replaces"`
	SideEffects          []string     `json:"side_effects"`
	SizeCompressed       int64        `json:"size_compressed"`
	SizeInstalled        int64        `json:"size_installed"`
	Hash                 Hash         `json:"hash"`
	URL                  string       `json:"url"`
	Build                Build        `json:"build"`
}

// Dependency mirrors PSD-009 §4.1.1 (and the subset that appears in
// indexes per §6.2.4). Constraint and Arch use omitempty so a bare-name
// entry emits canonical {"name":"..."}.
type Dependency struct {
	Name       string `json:"name"`
	Constraint string `json:"constraint,omitempty"`
	Arch       string `json:"arch,omitempty"`
}

// Provides mirrors §4.1.4.
type Provides struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Replaces mirrors §4.1.5.
type Replaces struct {
	Name       string `json:"name"`
	Constraint string `json:"constraint,omitempty"`
}

// Hash is the index entry's hash object (§6.2.6). Algorithm is fixed at
// "sha256" in v0.22; Value is lowercase hex.
type Hash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// Build is the per-package build provenance subset that appears in index
// entries (§6.2.4). It is intentionally smaller than the manifest's
// build object: source_ref is omitted from the index because it is long
// and low-information-density (consult the package directly when
// needed).
type Build struct {
	Timestamp string `json:"timestamp"`
	FarmID    string `json:"farm_id"`
}

// Encode returns the canonical on-wire form of i: compact JSON, no HTML
// escaping, single trailing newline. Encode does NOT sort or validate.
// Use SortActive or SortArchive to put Packages in the correct order
// before encoding.
//
// Nil array fields on Package are normalised to empty arrays during
// encoding (matching the manifest convention: nil vs absent are
// equivalent semantically, but `null` and `[]` differ at the byte level
// and we always emit `[]` for byte-stability).
func Encode(i Index) ([]byte, error) {
	for k := range i.Packages {
		normalisePackage(&i.Packages[k])
	}
	if i.Packages == nil {
		i.Packages = []Package{}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(i); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func normalisePackage(p *Package) {
	if p.Dependencies == nil {
		p.Dependencies = []Dependency{}
	}
	if p.OptionalDependencies == nil {
		p.OptionalDependencies = []Dependency{}
	}
	if p.Conflicts == nil {
		p.Conflicts = []Dependency{}
	}
	if p.Provides == nil {
		p.Provides = []Provides{}
	}
	if p.Replaces == nil {
		p.Replaces = []Replaces{}
	}
	if p.SideEffects == nil {
		p.SideEffects = []string{}
	}
}

// SortActive sorts pkgs lexicographically by Name (§6.2.7). The active
// index's per-name uniqueness invariant (§6.2.7) is enforced by the
// caller; SortActive does not check or deduplicate.
func SortActive(pkgs []Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].Name < pkgs[j].Name
	})
}

// SortArchive sorts pkgs by Name ascending, then within each name group
// by Version DESCENDING (§6.3.5). Newest version of each name appears
// first within its group; consumers scanning for "satisfying constraint
// X" can stop scanning a name group as soon as the constraint is
// satisfied or exceeded.
//
// Returns an error if any package's Version is not parsable per §2.2 —
// the comparator needs structured versions.
func SortArchive(pkgs []Package) error {
	// Pre-validate every version so the comparator below can rely on
	// Parse never failing. Cheap (microseconds per parse).
	for _, p := range pkgs {
		if _, err := version.Parse(p.Version); err != nil {
			return fmt.Errorf("package %s: parse version %q: %w", p.Name, p.Version, err)
		}
	}

	sort.SliceStable(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		// Same name: descending by version (§6.3.5). Re-parsing here
		// is wasteful but bounded — same-name groups are small (typical
		// O(10s) of versions per package name), and the comparator
		// only triggers on equal names. Pre-validation above ensures
		// the parses cannot fail.
		a, _ := version.Parse(pkgs[i].Version)
		b, _ := version.Parse(pkgs[j].Version)
		return version.Compare(a, b) > 0
	})
	return nil
}

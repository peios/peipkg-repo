// Package descriptor defines the on-wire schema and canonical encoding
// for a repository descriptor (PSD-009 §6.1) — the `repo.json` document
// served at the repository's well-known root URL.
//
// As elsewhere, struct field declaration order is the on-wire byte order;
// reordering fields here changes the bytes a producer emits.
package descriptor

import (
	"bytes"
	"encoding/json"
)

// SchemaVersion is the descriptor schema version this package emits.
const SchemaVersion = 1

// Algorithm is the signature-algorithm identifier this package emits.
// PSD-009 v0.22 mandates Ed25519 only (§5.2.1).
const Algorithm = "ed25519"

// Key statuses defined by §6.1.4.
const (
	StatusActive        = "active"
	StatusTransitioning = "transitioning"
	StatusRevoked       = "revoked"
)

// Descriptor is the document published at <repo-base>/repo.json.
type Descriptor struct {
	SchemaVersion int     `json:"schema_version"`
	Repo          Repo    `json:"repo"`
	Indexes       Indexes `json:"indexes"`
}

// Repo carries the repository's identity and signing configuration.
//
// Description is optional (§6.1.2). The canonical encoder always emits
// an empty string when absent so the output is byte-stable regardless of
// whether the operator supplied a description.
type Repo struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Signing     Signing `json:"signing"`
}

// Signing holds the algorithm identifier and the array of keys that
// participate in this repository's signing trust set.
type Signing struct {
	Algorithm string `json:"algorithm"`
	Keys      []Key  `json:"keys"`
}

// Key is one entry in the descriptor's signing-keys array (§6.1.3).
//
// ValidUntil uses omitempty: it is required only for keys with
// status="transitioning" (§6.1.4), forbidden in semantics for the other
// statuses. Producers that emit a transitioning key MUST set ValidUntil;
// the descriptor encoder does not enforce that — the operator-facing
// init/publish layer does.
type Key struct {
	Fingerprint string `json:"fingerprint"`
	URL         string `json:"url"`
	Status      string `json:"status"`
	ValidUntil  string `json:"valid_until,omitempty"`
}

// Indexes points at the active and archive indexes. Both are REQUIRED in
// every descriptor, even when the archive contains zero historical
// versions (§6.1.2 makes the archive pointer required).
type Indexes struct {
	Active  Pointer `json:"active"`
	Archive Pointer `json:"archive"`
}

// Pointer is one entry in the indexes object: the URL of an index file
// and its detached signature (§6.1.5). Both URLs MAY be relative to
// <repo-base>; the canonical paths are /index/active.json[.sig] and
// /index/archive.json[.sig].
type Pointer struct {
	URL          string `json:"url"`
	SignatureURL string `json:"signature_url"`
}

// Encode returns the canonical on-wire form of d: compact JSON with no
// HTML escaping, terminated by a single newline. The bytes are
// reproducible for a given Descriptor value, which is what makes
// descriptor signing meaningful.
//
// Encode does NOT sort or validate. Callers must pre-sort
// Repo.Signing.Keys lex by Fingerprint (§6.1.3) and ensure the descriptor
// is otherwise spec-conformant.
func Encode(d Descriptor) ([]byte, error) {
	if d.Repo.Signing.Keys == nil {
		d.Repo.Signing.Keys = []Key{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

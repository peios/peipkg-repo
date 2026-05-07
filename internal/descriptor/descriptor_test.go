package descriptor

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeSpecExample(t *testing.T) {
	// Replicates the §6.1.7 example, modulo the abbreviated fingerprint.
	d := Descriptor{
		SchemaVersion: SchemaVersion,
		Repo: Repo{
			Name:        "peios-official",
			Description: "Official Peios package repository",
			Signing: Signing{
				Algorithm: Algorithm,
				Keys: []Key{
					{
						Fingerprint: strings.Repeat("a", 64),
						URL:         "/keys/" + strings.Repeat("a", 64) + ".pub",
						Status:      StatusActive,
					},
				},
			},
		},
		Indexes: Indexes{
			Active:  Pointer{URL: "/index/active.json", SignatureURL: "/index/active.json.sig"},
			Archive: Pointer{URL: "/index/archive.json", SignatureURL: "/index/archive.json.sig"},
		},
	}
	got, err := Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(got, []byte("\n")) {
		t.Error("missing trailing newline")
	}
	// Spot-check field order. Each marker is a unique-in-the-output key
	// label so a naive substring scan finds the field rather than a value.
	wantOrder := []string{
		`"schema_version"`, `"repo"`, `"name"`, `"description"`, `"signing"`,
		`"algorithm"`, `"keys"`, `"fingerprint"`,
		`"indexes"`,
	}
	s := string(got)
	last := -1
	for _, k := range wantOrder {
		i := strings.Index(s, k)
		if i < 0 {
			t.Errorf("missing field %s in output:\n%s", k, s)
			continue
		}
		if i <= last {
			t.Errorf("field %s out of order", k)
		}
		last = i
	}
}

func TestValidUntilOmittedForActive(t *testing.T) {
	d := Descriptor{
		SchemaVersion: SchemaVersion,
		Repo: Repo{
			Name: "x",
			Signing: Signing{
				Algorithm: Algorithm,
				Keys: []Key{
					{Fingerprint: strings.Repeat("a", 64), URL: "/k", Status: StatusActive},
				},
			},
		},
	}
	got, err := Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("valid_until")) {
		t.Errorf("active key emitted valid_until:\n%s", got)
	}
}

func TestValidUntilEmittedForTransitioning(t *testing.T) {
	d := Descriptor{
		SchemaVersion: SchemaVersion,
		Repo: Repo{
			Name: "x",
			Signing: Signing{
				Algorithm: Algorithm,
				Keys: []Key{
					{
						Fingerprint: strings.Repeat("a", 64),
						URL:         "/k",
						Status:      StatusTransitioning,
						ValidUntil:  "2026-12-31T00:00:00Z",
					},
				},
			},
		},
	}
	got, err := Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"valid_until":"2026-12-31T00:00:00Z"`)) {
		t.Errorf("transitioning key did not emit valid_until:\n%s", got)
	}
}

func TestEncodeNilKeysNormalize(t *testing.T) {
	d := Descriptor{
		SchemaVersion: SchemaVersion,
		Repo: Repo{
			Name: "x",
			Signing: Signing{
				Algorithm: Algorithm,
				Keys:      nil,
			},
		},
	}
	got, err := Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"keys":[]`)) {
		t.Errorf("nil keys should encode as []:\n%s", got)
	}
}

func TestEncodeNoHTMLEscape(t *testing.T) {
	d := Descriptor{
		Repo: Repo{Description: "<example> & friends"},
	}
	got, err := Encode(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("<example> & friends")) {
		t.Errorf("HTML chars escaped:\n%s", got)
	}
}

package index

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeMinimal(t *testing.T) {
	idx := Index{
		SchemaVersion: SchemaVersion,
		Repo:          "test-repo",
		Kind:          KindActive,
		IndexVersion:  1,
		GeneratedAt:   "2026-05-07T00:00:00Z",
	}
	got, err := Encode(idx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(got, []byte("\n")) {
		t.Error("missing trailing newline")
	}
	if !bytes.Contains(got, []byte(`"packages":[]`)) {
		t.Errorf("nil packages should encode as []:\n%s", got)
	}
}

func TestEncodeNormalizesPackageArrays(t *testing.T) {
	idx := Index{
		SchemaVersion: SchemaVersion,
		Repo:          "r",
		Kind:          KindActive,
		IndexVersion:  1,
		GeneratedAt:   "2026-05-07T00:00:00Z",
		Packages: []Package{{
			Name:           "x",
			Version:        "1.0-1",
			Architecture:   "noarch",
			SizeCompressed: 100,
			SizeInstalled:  200,
			Hash:           Hash{Algorithm: HashAlgorithm, Value: strings.Repeat("a", 64)},
			URL:            "/p/x/1.0-1/x_1.0-1_noarch.peipkg",
		}},
	}
	got, err := Encode(idx)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"dependencies":[]`,
		`"optional_dependencies":[]`,
		`"conflicts":[]`,
		`"provides":[]`,
		`"replaces":[]`,
		`"side_effects":[]`,
	} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("output missing %s:\n%s", want, got)
		}
	}
	if bytes.Contains(got, []byte(`null`)) {
		t.Errorf("output contains null literal:\n%s", got)
	}
}

func TestSortActiveByName(t *testing.T) {
	pkgs := []Package{
		{Name: "zebra"},
		{Name: "apple"},
		{Name: "mango"},
	}
	SortActive(pkgs)
	want := []string{"apple", "mango", "zebra"}
	for i, p := range pkgs {
		if p.Name != want[i] {
			t.Errorf("pkgs[%d].Name = %q, want %q", i, p.Name, want[i])
		}
	}
}

func TestSortArchiveByNameAscThenVersionDesc(t *testing.T) {
	pkgs := []Package{
		{Name: "libfoo", Version: "1.0.0-1"},
		{Name: "libbar", Version: "2.5-1"},
		{Name: "libfoo", Version: "1.2.0-1"},
		{Name: "libfoo", Version: "1.1.0-1"},
		{Name: "libbar", Version: "2.4-1"},
	}
	if err := SortArchive(pkgs); err != nil {
		t.Fatal(err)
	}
	want := []struct{ name, version string }{
		{"libbar", "2.5-1"}, // highest libbar first
		{"libbar", "2.4-1"},
		{"libfoo", "1.2.0-1"}, // highest libfoo first
		{"libfoo", "1.1.0-1"},
		{"libfoo", "1.0.0-1"},
	}
	if len(pkgs) != len(want) {
		t.Fatalf("length mismatch")
	}
	for i, w := range want {
		if pkgs[i].Name != w.name || pkgs[i].Version != w.version {
			t.Errorf("pkgs[%d] = (%s, %s), want (%s, %s)",
				i, pkgs[i].Name, pkgs[i].Version, w.name, w.version)
		}
	}
}

func TestSortArchiveRejectsBadVersion(t *testing.T) {
	pkgs := []Package{
		{Name: "x", Version: "not-a-real-version"},
	}
	if err := SortArchive(pkgs); err == nil {
		t.Error("SortArchive accepted unparseable version")
	}
}

func TestEncodeFieldOrder(t *testing.T) {
	idx := Index{
		SchemaVersion: SchemaVersion,
		Repo:          "r",
		Kind:          KindActive,
		IndexVersion:  42,
		GeneratedAt:   "2026-05-07T00:00:00Z",
	}
	got, err := Encode(idx)
	if err != nil {
		t.Fatal(err)
	}
	wantOrder := []string{
		`"schema_version"`, `"repo"`, `"kind"`,
		`"index_version"`, `"generated_at"`, `"packages"`,
	}
	s := string(got)
	last := -1
	for _, k := range wantOrder {
		i := strings.Index(s, k)
		if i < 0 {
			t.Errorf("missing %s in output:\n%s", k, s)
			continue
		}
		if i <= last {
			t.Errorf("field %s out of order", k)
		}
		last = i
	}
}

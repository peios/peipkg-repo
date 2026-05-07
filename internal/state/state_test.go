package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/peios/peipkg-repo/internal/descriptor"
	"github.com/peios/peipkg-repo/internal/index"
	"github.com/peios/peipkg-repo/internal/signature"
)

// makeKey returns a deterministic Ed25519 key for tests. The seed is
// fixed so multiple test runs produce identical keys (and identical
// signed bytes, which makes deterministic-output assertions tractable).
func makeKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	priv, pub := makeKey(t)
	fp := signature.Fingerprint(pub)

	desc := descriptor.Descriptor{
		SchemaVersion: descriptor.SchemaVersion,
		Repo: descriptor.Repo{
			Name:        "round-trip-test",
			Description: "test fixture",
			Signing: descriptor.Signing{
				Algorithm: descriptor.Algorithm,
				Keys: []descriptor.Key{
					{Fingerprint: fp, URL: "/keys/" + fp + ".pub", Status: descriptor.StatusActive},
				},
			},
		},
		Indexes: descriptor.Indexes{
			Active:  descriptor.Pointer{URL: "/index/active.json", SignatureURL: "/index/active.json.sig"},
			Archive: descriptor.Pointer{URL: "/index/archive.json", SignatureURL: "/index/archive.json.sig"},
		},
	}
	active := index.Index{
		SchemaVersion: index.SchemaVersion,
		Repo:          desc.Repo.Name,
		Kind:          index.KindActive,
		IndexVersion:  1,
		GeneratedAt:   "2026-05-07T00:00:00Z",
	}
	archive := index.Index{
		SchemaVersion: index.SchemaVersion,
		Repo:          desc.Repo.Name,
		Kind:          index.KindArchive,
		IndexVersion:  1,
		GeneratedAt:   "2026-05-07T00:00:00Z",
	}

	if err := Save(dir, desc, active, archive, priv); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := WriteKeyFile(dir, fp, pub); err != nil {
		t.Fatalf("WriteKeyFile: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Descriptor.Repo.Name != "round-trip-test" {
		t.Errorf("Descriptor.Repo.Name = %q, want round-trip-test", loaded.Descriptor.Repo.Name)
	}
	if loaded.Active.IndexVersion != 1 {
		t.Errorf("Active.IndexVersion = %d, want 1", loaded.Active.IndexVersion)
	}
	if loaded.Archive.Kind != index.KindArchive {
		t.Errorf("Archive.Kind = %q, want %q", loaded.Archive.Kind, index.KindArchive)
	}

	// The detached signatures must verify against pub.
	for _, c := range []struct {
		name string
		body []byte
		env  *signature.Envelope
	}{
		{"descriptor", loaded.DescriptorBytes, loaded.DescriptorSig},
		{"active", loaded.ActiveBytes, loaded.ActiveSig},
		{"archive", loaded.ArchiveBytes, loaded.ArchiveSig},
	} {
		if c.env == nil {
			t.Errorf("%s: signature missing", c.name)
			continue
		}
		if c.env.KeyFingerprint != fp {
			t.Errorf("%s: fingerprint = %q, want %q", c.name, c.env.KeyFingerprint, fp)
		}
		sig, err := base64.RawStdEncoding.DecodeString(c.env.Signature)
		if err != nil {
			t.Errorf("%s: decode signature: %v", c.name, err)
			continue
		}
		digest := sha256.Sum256(c.body)
		if !ed25519.Verify(pub, digest[:], sig) {
			t.Errorf("%s: signature does not verify", c.name)
		}
	}
}

func TestSaveDeterministic(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()
	priv, _ := makeKey(t)

	desc := descriptor.Descriptor{
		SchemaVersion: descriptor.SchemaVersion,
		Repo: descriptor.Repo{
			Name:    "det",
			Signing: descriptor.Signing{Algorithm: descriptor.Algorithm},
		},
	}
	active := index.Index{
		SchemaVersion: index.SchemaVersion,
		Repo:          "det",
		Kind:          index.KindActive,
		IndexVersion:  1,
		GeneratedAt:   "2026-05-07T00:00:00Z",
	}
	archive := index.Index{
		SchemaVersion: index.SchemaVersion,
		Repo:          "det",
		Kind:          index.KindArchive,
		IndexVersion:  1,
		GeneratedAt:   "2026-05-07T00:00:00Z",
	}

	if err := Save(dirA, desc, active, archive, priv); err != nil {
		t.Fatal(err)
	}
	if err := Save(dirB, desc, active, archive, priv); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{
		"repo.json", "repo.json.sig",
		filepath.Join("index", "active.json"), filepath.Join("index", "active.json.sig"),
		filepath.Join("index", "archive.json"), filepath.Join("index", "archive.json.sig"),
	} {
		a, err := os.ReadFile(filepath.Join(dirA, p))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dirB, p))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s not byte-deterministic across two saves", p)
		}
	}
}

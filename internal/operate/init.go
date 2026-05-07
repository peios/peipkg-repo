package operate

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/peios/peipkg-repo/internal/descriptor"
	"github.com/peios/peipkg-repo/internal/index"
	"github.com/peios/peipkg-repo/internal/signature"
	"github.com/peios/peipkg-repo/internal/state"
)

// InitConfig configures Init.
type InitConfig struct {
	// Name is the repository's identity. Required, non-empty, kebab-case
	// recommended (§6.1.2).
	Name string

	// Description is a human-readable one-line description. Optional;
	// empty string is permitted (§6.1.2).
	Description string

	// SignKey is the operator's Ed25519 private key. Its public half is
	// recorded in the descriptor as the sole `active` signing key.
	SignKey ed25519.PrivateKey

	// Timestamp is the RFC 3339 UTC timestamp recorded as `generated_at`
	// in the empty initial indexes. Must end with 'Z'. Required so init
	// is reproducible.
	Timestamp string

	// Out is the directory the new state is written into. Created if
	// missing; must be empty if it exists (Init refuses to overwrite an
	// existing repository to prevent accidental destruction).
	Out string
}

// Init creates a fresh repository state at cfg.Out: a descriptor that
// declares cfg.SignKey as the sole active signing key, an empty active
// index at index_version 1, an empty archive index at index_version 1,
// detached signatures over each, and the public-key file under keys/.
//
// Init refuses to write into a non-empty directory; the operator must
// `peipkg-repo init` once for each new repository, against an empty
// or non-existent --out.
func Init(cfg InitConfig) error {
	if err := validateInit(cfg); err != nil {
		return err
	}
	if err := requireEmptyDir(cfg.Out); err != nil {
		return err
	}

	pub := cfg.SignKey.Public().(ed25519.PublicKey)
	fp := signature.Fingerprint(pub)

	desc := descriptor.Descriptor{
		SchemaVersion: descriptor.SchemaVersion,
		Repo: descriptor.Repo{
			Name:        cfg.Name,
			Description: cfg.Description,
			Signing: descriptor.Signing{
				Algorithm: descriptor.Algorithm,
				Keys: []descriptor.Key{
					{
						Fingerprint: fp,
						URL:         "/keys/" + fp + ".pub",
						Status:      descriptor.StatusActive,
					},
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
		Repo:          cfg.Name,
		Kind:          index.KindActive,
		IndexVersion:  1,
		GeneratedAt:   cfg.Timestamp,
	}
	archive := index.Index{
		SchemaVersion: index.SchemaVersion,
		Repo:          cfg.Name,
		Kind:          index.KindArchive,
		IndexVersion:  1,
		GeneratedAt:   cfg.Timestamp,
	}

	if err := state.Save(cfg.Out, desc, active, archive, cfg.SignKey); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	if err := state.WriteKeyFile(cfg.Out, fp, pub); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

func validateInit(cfg InitConfig) error {
	switch {
	case cfg.Name == "":
		return fmt.Errorf("Name is required")
	case len(cfg.SignKey) == 0:
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
	return nil
}

// requireEmptyDir returns nil if dir does not exist or exists but is
// empty. Returns an error if dir contains any entries — Init refuses to
// stomp on existing state.
func requireEmptyDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", dir, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s is not empty (Init refuses to overwrite existing state; use a fresh directory)", dir)
	}
	return nil
}

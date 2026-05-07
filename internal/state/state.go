// Package state reads and writes a peipkg-repo state directory: the
// publishable tree containing the descriptor, indexes, and their
// detached signatures, laid out per PSD-009 §6.4 conventional paths.
//
// State is the on-disk representation of a repository at a moment in
// time. peipkg-repo's three operations (init, publish, verify) all
// load a previous state, mutate it, and save a new one (init starts
// from nothing; verify reads-only).
//
// Layout produced by Save:
//
//	<dir>/repo.json
//	<dir>/repo.json.sig
//	<dir>/index/active.json
//	<dir>/index/active.json.sig
//	<dir>/index/archive.json
//	<dir>/index/archive.json.sig
//
// The keys/ directory under <dir> holds public-key files. Save does not
// write or read public-key files — that is the caller's concern (init
// writes one .pub during repository creation; key rotation, when added,
// will manage them too).
package state

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/peios/peipkg-repo/internal/descriptor"
	"github.com/peios/peipkg-repo/internal/index"
	"github.com/peios/peipkg-repo/internal/signature"
)

// File names within a state directory. These match §6.4 conventional
// paths and are not configurable.
const (
	descriptorFile    = "repo.json"
	descriptorSigFile = "repo.json.sig"
	indexDir          = "index"
	activeFile        = "active.json"
	activeSigFile     = "active.json.sig"
	archiveFile       = "archive.json"
	archiveSigFile    = "archive.json.sig"
	keysDir           = "keys"
)

// State is a loaded repository state directory.
//
// Each file's raw bytes are kept alongside the parsed form so that
// verify can re-hash and re-verify signatures without re-encoding
// (encoding is deterministic but the bytes are what was signed; we
// trust the bytes, not the re-encode).
//
// Sig fields are nil when the corresponding .sig file is absent —
// permitted under §6.5.3's "optional" trust policy. Verify treats nil
// sigs as a policy decision to surface to the operator.
type State struct {
	Descriptor      descriptor.Descriptor
	DescriptorBytes []byte
	DescriptorSig   *signature.Envelope

	Active      index.Index
	ActiveBytes []byte
	ActiveSig   *signature.Envelope

	Archive      index.Index
	ArchiveBytes []byte
	ArchiveSig   *signature.Envelope
}

// Load reads a state directory from dir. The descriptor and both
// indexes MUST be present; signature files are optional.
func Load(dir string) (*State, error) {
	s := &State{}

	descBytes, err := os.ReadFile(filepath.Join(dir, descriptorFile))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", descriptorFile, err)
	}
	if err := json.Unmarshal(descBytes, &s.Descriptor); err != nil {
		return nil, fmt.Errorf("parse %s: %w", descriptorFile, err)
	}
	s.DescriptorBytes = descBytes
	s.DescriptorSig, err = loadSig(filepath.Join(dir, descriptorSigFile))
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", descriptorSigFile, err)
	}

	activeBytes, err := os.ReadFile(filepath.Join(dir, indexDir, activeFile))
	if err != nil {
		return nil, fmt.Errorf("read %s/%s: %w", indexDir, activeFile, err)
	}
	if err := json.Unmarshal(activeBytes, &s.Active); err != nil {
		return nil, fmt.Errorf("parse %s/%s: %w", indexDir, activeFile, err)
	}
	s.ActiveBytes = activeBytes
	s.ActiveSig, err = loadSig(filepath.Join(dir, indexDir, activeSigFile))
	if err != nil {
		return nil, fmt.Errorf("load %s/%s: %w", indexDir, activeSigFile, err)
	}

	archiveBytes, err := os.ReadFile(filepath.Join(dir, indexDir, archiveFile))
	if err != nil {
		return nil, fmt.Errorf("read %s/%s: %w", indexDir, archiveFile, err)
	}
	if err := json.Unmarshal(archiveBytes, &s.Archive); err != nil {
		return nil, fmt.Errorf("parse %s/%s: %w", indexDir, archiveFile, err)
	}
	s.ArchiveBytes = archiveBytes
	s.ArchiveSig, err = loadSig(filepath.Join(dir, indexDir, archiveSigFile))
	if err != nil {
		return nil, fmt.Errorf("load %s/%s: %w", indexDir, archiveSigFile, err)
	}

	return s, nil
}

// loadSig reads a detached signature file and parses its envelope.
// Returns (nil, nil) if the file does not exist (signatures are
// optional). Returns an error only on read or parse failure.
func loadSig(path string) (*signature.Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var env signature.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parse envelope: %w", err)
	}
	return &env, nil
}

// Save writes a fresh state to dir, encoding each document canonically
// and producing a detached signature for each. The descriptor and
// indexes are encoded via their respective Encode functions, signed
// with signKey, and written to the conventional §6.4 paths.
//
// Save creates dir, dir/index, and dir/keys if they do not exist. It
// does not write public key files — see WriteKeyFile for that.
func Save(dir string, d descriptor.Descriptor, active, archive index.Index, signKey ed25519.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := os.MkdirAll(filepath.Join(dir, indexDir), 0o755); err != nil {
		return fmt.Errorf("create %s/%s: %w", dir, indexDir, err)
	}
	if err := os.MkdirAll(filepath.Join(dir, keysDir), 0o755); err != nil {
		return fmt.Errorf("create %s/%s: %w", dir, keysDir, err)
	}

	descBytes, err := descriptor.Encode(d)
	if err != nil {
		return fmt.Errorf("encode descriptor: %w", err)
	}
	if err := writeSigned(filepath.Join(dir, descriptorFile), descBytes, signKey); err != nil {
		return fmt.Errorf("write descriptor: %w", err)
	}

	activeBytes, err := index.Encode(active)
	if err != nil {
		return fmt.Errorf("encode active index: %w", err)
	}
	if err := writeSigned(filepath.Join(dir, indexDir, activeFile), activeBytes, signKey); err != nil {
		return fmt.Errorf("write active index: %w", err)
	}

	archiveBytes, err := index.Encode(archive)
	if err != nil {
		return fmt.Errorf("encode archive index: %w", err)
	}
	if err := writeSigned(filepath.Join(dir, indexDir, archiveFile), archiveBytes, signKey); err != nil {
		return fmt.Errorf("write archive index: %w", err)
	}

	return nil
}

// writeSigned writes body to path and a detached signature envelope to
// path+".sig". The signature signs SHA-256(body) using signKey, per
// §6.1.6 / §6.2.1 / §6.3.2.
func writeSigned(path string, body []byte, signKey ed25519.PrivateKey) error {
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	envBytes, err := signature.Encode(signature.Sign(signKey, digest[:]))
	if err != nil {
		return fmt.Errorf("encode signature envelope for %s: %w", filepath.Base(path), err)
	}
	if err := os.WriteFile(path+".sig", envBytes, 0o644); err != nil {
		return err
	}
	return nil
}

// WriteKeyFile writes a public key in PEM SubjectPublicKeyInfo form to
// the conventional path keys/<fingerprint>.pub within dir. Used by init
// to publish the operator's signing key alongside the descriptor; not
// used by publish (which doesn't change the trust set).
func WriteKeyFile(dir, fingerprint string, pub ed25519.PublicKey) error {
	if err := os.MkdirAll(filepath.Join(dir, keysDir), 0o755); err != nil {
		return err
	}
	pem, err := signature.EncodePublicKey(pub)
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	path := filepath.Join(dir, keysDir, fingerprint+".pub")
	return os.WriteFile(path, pem, 0o644)
}

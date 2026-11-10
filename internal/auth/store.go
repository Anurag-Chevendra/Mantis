package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/zalando/go-keyring"
)

// Credential is what `mantis login` keeps.
type Credential struct {
	Host      string    `json:"host"`  // API host the key belongs to
	Token     string    `json:"token"` // the API key itself
	Scope     string    `json:"scope,omitempty"`
	Device    string    `json:"device,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// Prefix is the first characters of the key, safe to print.
func (c Credential) Prefix() string {
	if len(c.Token) <= 16 {
		return "****"
	}
	return c.Token[:16] + "…"
}

// Store persists credentials.
type Store interface {
	Get(host string) (*Credential, error)
	Set(c *Credential) error
	Delete(host string) error
	Name() string
}

// ErrNotFound means no credential is stored for the host.
var ErrNotFound = errors.New("not logged in")

const keyringService = "mantis"

// Keyring stores credentials in the operating system's credential store:
// macOS Keychain, Windows Credential Manager, or the Secret Service on Linux
// (GNOME Keyring, KWallet). This is the default.
type Keyring struct{}

func (Keyring) Name() string {
	switch runtime.GOOS {
	case "darwin":
		return "macOS Keychain"
	case "windows":
		return "Windows Credential Manager"
	default:
		return "system keyring (Secret Service)"
	}
}

func (Keyring) Get(host string) (*Credential, error) {
	s, err := keyring.Get(keyringService, host)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var c Credential
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return nil, fmt.Errorf("stored credential is corrupt; run `mantis logout` then `mantis login`")
	}
	return &c, nil
}

func (Keyring) Set(c *Credential) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return keyring.Set(keyringService, c.Host, string(b))
}

func (Keyring) Delete(host string) error {
	err := keyring.Delete(keyringService, host)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// File stores credentials in a JSON file readable only by the current user.
// It is used only when the user opts in with --insecure-storage, for machines
// with no keyring (headless Linux, containers).
type File struct{ Path string }

// DefaultFilePath is <user config dir>/mantis/credentials.json.
func DefaultFilePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "mantis", "credentials.json"), nil
}

func (f File) Name() string { return "file " + f.Path }

func (f File) load() (map[string]*Credential, error) {
	m := map[string]*Credential{}
	info, err := os.Stat(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users (mode %o); run: chmod 600 %s", f.Path, info.Mode().Perm(), f.Path)
	}
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%s is corrupt: %w", f.Path, err)
	}
	return m, nil
}

func (f File) save(m map[string]*Credential) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}

func (f File) Get(host string) (*Credential, error) {
	m, err := f.load()
	if err != nil {
		return nil, err
	}
	c, ok := m[host]
	if !ok {
		return nil, ErrNotFound
	}
	return c, nil
}

func (f File) Set(c *Credential) error {
	m, err := f.load()
	if err != nil {
		return err
	}
	m[c.Host] = c
	return f.save(m)
}

func (f File) Delete(host string) error {
	m, err := f.load()
	if err != nil {
		return err
	}
	if _, ok := m[host]; !ok {
		return ErrNotFound
	}
	delete(m, host)
	if len(m) == 0 {
		return os.Remove(f.Path)
	}
	return f.save(m)
}

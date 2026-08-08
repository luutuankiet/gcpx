// Package store persists identities as one metadata + credential file pair
// per alias. There is deliberately no central registry file: two agents
// operating on two different identities never contend, and a corrupted write
// can only damage one identity.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Lifecycle states.
const (
	StateActive   = "active"
	StateStale    = "stale"
	StateScopeGap = "scope-gap"
	StateExpired  = "expired"
	StateArchived = "archived"
)

// ErrNotFound is returned when an alias has no metadata file.
var ErrNotFound = errors.New("identity not found")

// Identity is the metadata sidecar for one credential. The ADC file format
// records neither scopes nor a usable account, so everything an operator or
// an agent needs to choose a credential lives here instead.
type Identity struct {
	Alias          string    `json:"alias"`
	Email          string    `json:"email"`
	Description    string    `json:"description,omitempty"`
	DefaultProject string    `json:"default_project,omitempty"`
	KnownProjects  []string  `json:"known_projects,omitempty"`
	Scopes         []string  `json:"scopes"`
	Tags           []string  `json:"tags,omitempty"`
	MintedAt       time.Time `json:"minted_at"`
	LastVerifiedAt time.Time `json:"last_verified_at"`
	LastError      string    `json:"last_error,omitempty"`
	State          string    `json:"state"`
	Note           string    `json:"note,omitempty"`
}

var aliasRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidAlias enforces a filesystem-safe, lowercase alias.
func ValidAlias(a string) error {
	if !aliasRe.MatchString(a) {
		return fmt.Errorf("invalid alias %q: use lowercase letters, digits, dot, dash, underscore (max 64, must start alphanumeric)", a)
	}
	return nil
}

func home() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return h
}

// DataDir is where identities live. GCPX_HOME overrides everything, which is
// what makes the test suite and throwaway sandboxes possible.
func DataDir() string {
	if v := os.Getenv("GCPX_HOME"); v != "" {
		return v
	}
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, "gcpx")
	}
	return filepath.Join(home(), ".local", "share", "gcpx")
}

// StateDir holds caches and logs, not credentials.
func StateDir() string {
	if v := os.Getenv("GCPX_STATE"); v != "" {
		return v
	}
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, "gcpx")
	}
	return filepath.Join(home(), ".local", "state", "gcpx")
}

func IdentitiesDir() string     { return filepath.Join(DataDir(), "identities") }
func ArchiveDir() string        { return filepath.Join(DataDir(), "archive") }
func ConfigDir(a string) string { return filepath.Join(DataDir(), "cfg", a) }
func MetaPath(a string) string  { return filepath.Join(IdentitiesDir(), a+".json") }
func ADCPath(a string) string   { return filepath.Join(IdentitiesDir(), a+".adc.json") }
func LogPath() string           { return filepath.Join(StateDir(), "refresh.log") }

// EnsureDirs creates the store layout. Identity dirs are 0700 because they
// hold live OAuth refresh tokens.
func EnsureDirs() error {
	for _, d := range []string{DataDir(), IdentitiesDir(), ArchiveDir(), StateDir(), filepath.Join(DataDir(), "cfg")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// writeAtomic writes via a tempfile in the SAME directory then renames.
// Same-directory matters: a cross-filesystem rename silently degrades to a
// copy and stops being atomic.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp.*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Exists reports whether an active (non-archived) identity holds the alias.
func Exists(alias string) bool {
	_, err := os.Stat(MetaPath(alias))
	return err == nil
}

// Load reads one identity's metadata.
func Load(alias string) (Identity, error) {
	var id Identity
	b, err := os.ReadFile(MetaPath(alias))
	if err != nil {
		if os.IsNotExist(err) {
			return id, fmt.Errorf("%w: %s", ErrNotFound, alias)
		}
		return id, err
	}
	if err := json.Unmarshal(b, &id); err != nil {
		return id, fmt.Errorf("corrupt metadata %s: %w", MetaPath(alias), err)
	}
	if id.Alias == "" {
		id.Alias = alias
	}
	return id, nil
}

// Save writes identity metadata atomically.
func Save(id Identity) error {
	if err := ValidAlias(id.Alias); err != nil {
		return err
	}
	if err := EnsureDirs(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(MetaPath(id.Alias), append(b, '\n'), 0o600)
}

// SaveADC writes the credential file, 0600, atomically.
func SaveADC(alias string, raw []byte) error {
	if err := ValidAlias(alias); err != nil {
		return err
	}
	if err := EnsureDirs(); err != nil {
		return err
	}
	return writeAtomic(ADCPath(alias), raw, 0o600)
}

// LoadADC reads the raw credential bytes.
func LoadADC(alias string) ([]byte, error) {
	b, err := os.ReadFile(ADCPath(alias))
	if err != nil && os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: no credential file for %s", ErrNotFound, alias)
	}
	return b, err
}

func listDir(dir string) ([]Identity, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Identity
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".json") || strings.HasSuffix(n, ".adc.json") || strings.HasPrefix(n, ".") {
			continue
		}
		var id Identity
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		if err := json.Unmarshal(b, &id); err != nil {
			continue
		}
		if id.Alias == "" {
			id.Alias = strings.TrimSuffix(n, ".json")
		}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out, nil
}

// List returns active identities, alias-sorted.
func List() ([]Identity, error) { return listDir(IdentitiesDir()) }

// ListArchived returns retired identities, alias-sorted.
func ListArchived() ([]Identity, error) { return listDir(ArchiveDir()) }

// Archive retires an identity: the file pair moves aside, the alias frees up,
// and the credential is kept for audit rather than destroyed.
func Archive(alias string) error {
	id, err := Load(alias)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(ArchiveDir(), 0o700); err != nil {
		return err
	}
	id.State = StateArchived
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	dst := filepath.Join(ArchiveDir(), alias+"."+stamp+".json")
	if err := writeAtomic(dst, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if raw, err := LoadADC(alias); err == nil {
		if err := writeAtomic(filepath.Join(ArchiveDir(), alias+"."+stamp+".adc.json"), raw, 0o600); err != nil {
			return err
		}
		_ = os.Remove(ADCPath(alias))
	}
	if err := os.Remove(MetaPath(alias)); err != nil {
		return err
	}
	_ = os.RemoveAll(ConfigDir(alias))
	return nil
}

// Remove deletes an identity outright. Archive is almost always the better
// choice; this exists for credentials that must not persist at all.
func Remove(alias string) error {
	if !Exists(alias) {
		return fmt.Errorf("%w: %s", ErrNotFound, alias)
	}
	_ = os.Remove(ADCPath(alias))
	_ = os.RemoveAll(ConfigDir(alias))
	return os.Remove(MetaPath(alias))
}

// EnsureConfigDir creates a per-identity CLOUDSDK_CONFIG directory seeded
// with a project setting. Isolating the config dir per identity keeps gcloud's
// shared access-token SQLite cache from becoming a contention point when many
// agents run concurrently against different credentials.
func EnsureConfigDir(alias, project string) (string, error) {
	dir := ConfigDir(alias)
	if err := os.MkdirAll(filepath.Join(dir, "configurations"), 0o700); err != nil {
		return "", err
	}
	cfg := filepath.Join(dir, "configurations", "config_default")
	body := "[core]\ndisable_usage_reporting = True\n"
	if project != "" {
		body += "project = " + project + "\n"
	}
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "active_config"), []byte("default"), 0o600); err != nil {
		return "", err
	}
	return dir, nil
}

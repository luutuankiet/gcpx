package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func withTempStore(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GCPX_HOME", dir)
	t.Setenv("GCPX_STATE", filepath.Join(dir, "state"))
	if err := EnsureDirs(); err != nil {
		t.Fatal(err)
	}
}

func TestValidAlias(t *testing.T) {
	ok := []string{"work", "client-dev", "a", "a.b_c-1"}
	bad := []string{"", "-lead", "UPPER", "has space", "has/slash", ".."}
	for _, a := range ok {
		if err := ValidAlias(a); err != nil {
			t.Errorf("ValidAlias(%q) unexpected error: %v", a, err)
		}
	}
	for _, a := range bad {
		if err := ValidAlias(a); err == nil {
			t.Errorf("ValidAlias(%q) should have failed", a)
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	withTempStore(t)
	in := Identity{
		Alias: "work", Email: "a@b.com", DefaultProject: "p1",
		Scopes: []string{"openid"}, MintedAt: time.Now().UTC().Truncate(time.Second),
		State: StateActive,
	}
	if err := Save(in); err != nil {
		t.Fatal(err)
	}
	out, err := Load("work")
	if err != nil {
		t.Fatal(err)
	}
	if out.Email != in.Email || out.DefaultProject != in.DefaultProject {
		t.Errorf("round trip mismatch: %+v", out)
	}
}

// Credential files hold live refresh tokens; a group- or world-readable mode
// is a real leak, not a style issue.
func TestADCPermissions(t *testing.T) {
	withTempStore(t)
	if err := SaveADC("work", []byte(`{"type":"authorized_user"}`)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(ADCPath("work"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("credential mode = %v, want 0600", fi.Mode().Perm())
	}
}

// The .adc.json suffix must never be mistaken for a metadata file, or every
// identity would appear twice.
func TestListIgnoresCredentialFiles(t *testing.T) {
	withTempStore(t)
	if err := Save(Identity{Alias: "work", State: StateActive}); err != nil {
		t.Fatal(err)
	}
	if err := SaveADC("work", []byte(`{"type":"authorized_user"}`)); err != nil {
		t.Fatal(err)
	}
	ids, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("List returned %d identities, want 1: %+v", len(ids), ids)
	}
}

func TestArchiveFreesAlias(t *testing.T) {
	withTempStore(t)
	if err := Save(Identity{Alias: "old", State: StateActive}); err != nil {
		t.Fatal(err)
	}
	if err := SaveADC("old", []byte(`{"type":"authorized_user"}`)); err != nil {
		t.Fatal(err)
	}
	if err := Archive("old"); err != nil {
		t.Fatal(err)
	}
	if Exists("old") {
		t.Error("alias should be free after archive")
	}
	arch, err := ListArchived()
	if err != nil {
		t.Fatal(err)
	}
	if len(arch) != 1 || arch[0].State != StateArchived {
		t.Errorf("archive contents wrong: %+v", arch)
	}
}

func TestLoadMissing(t *testing.T) {
	withTempStore(t)
	if _, err := Load("ghost"); err == nil {
		t.Error("expected an error for a missing identity")
	}
}

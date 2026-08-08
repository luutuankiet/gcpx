package scopes

import (
	"slices"
	"testing"
)

func TestExpandShortNames(t *testing.T) {
	cases := map[string]string{
		"drive":          Prefix + "drive",
		"sheets":         Prefix + "spreadsheets",
		"openid":         "openid",
		"email":          Prefix + "userinfo.email",
		Prefix + "drive": Prefix + "drive",
		"pubsub":         Prefix + "pubsub",
	}
	for in, want := range cases {
		if got := Expand(in); got != want {
			t.Errorf("Expand(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeInjectsMandatory(t *testing.T) {
	got := Normalize([]string{"bigquery"})
	for _, m := range Mandatory {
		if !slices.Contains(got, m) {
			t.Errorf("Normalize dropped mandatory scope %q: %v", m, got)
		}
	}
	if !slices.IsSorted(got) {
		t.Errorf("Normalize output not sorted: %v", got)
	}
}

func TestSortedDoesNotInject(t *testing.T) {
	got := Sorted([]string{"bigquery", "bigquery"})
	if len(got) != 1 || got[0] != Prefix+"bigquery" {
		t.Fatalf("Sorted = %v, want one bigquery entry", got)
	}
}

// A credential minted with cloud-platform must not be reported as missing
// bigquery: cloud-platform already covers it, and a false gap would send the
// operator through a pointless re-consent.
func TestCloudPlatformImpliesBigQuery(t *testing.T) {
	granted := []string{Prefix + "cloud-platform"}
	if m := Missing([]string{"bigquery"}, granted); len(m) != 0 {
		t.Errorf("expected no gap, got %v", m)
	}
}

func TestDriveFileDoesNotSatisfyDrive(t *testing.T) {
	granted := []string{Prefix + "drive.file", Prefix + "cloud-platform"}
	m := Missing([]string{"drive"}, granted)
	if len(m) != 1 || m[0] != Prefix+"drive" {
		t.Errorf("drive.file must not satisfy drive; got missing=%v", m)
	}
	if !WeakDrive(granted) {
		t.Error("WeakDrive should flag a drive.file-only credential")
	}
	if WeakDrive([]string{Prefix + "drive.file", Prefix + "drive"}) {
		t.Error("WeakDrive must not fire when full drive is present")
	}
}

func TestDriveImpliesReadonly(t *testing.T) {
	if m := Missing([]string{"drive.readonly"}, []string{Prefix + "drive"}); len(m) != 0 {
		t.Errorf("full drive should cover drive.readonly, got %v", m)
	}
}

func TestCanSelfIdentify(t *testing.T) {
	if CanSelfIdentify([]string{Prefix + "cloud-platform"}) {
		t.Error("cloud-platform alone cannot self-identify")
	}
	if !CanSelfIdentify([]string{"email"}) {
		t.Error("email short name should self-identify")
	}
}

func TestParse(t *testing.T) {
	got := Parse(" drive, bigquery\tsheets ")
	want := []string{"drive", "bigquery", "sheets"}
	if !slices.Equal(got, want) {
		t.Errorf("Parse = %v, want %v", got, want)
	}
}

func TestPresetsResolve(t *testing.T) {
	for _, n := range PresetNames() {
		if _, err := ResolvePreset(n); err != nil {
			t.Errorf("preset %q: %v", n, err)
		}
	}
	if _, err := ResolvePreset("nope"); err == nil {
		t.Error("unknown preset should error")
	}
}

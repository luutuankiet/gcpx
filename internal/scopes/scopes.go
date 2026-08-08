// Package scopes maps short scope names to full OAuth scope URLs, defines
// presets, and answers whether a granted scope set satisfies a required one.
package scopes

import (
	"fmt"
	"sort"
	"strings"
)

// Prefix is the common Google OAuth scope URL prefix.
const Prefix = "https://www.googleapis.com/auth/"

// Mandatory scopes are force-injected into every mint.
//
// openid + userinfo.email are what make a credential self-identifying: the
// ADC file itself carries no email, so tokeninfo is the only way to learn who
// a credential belongs to, and tokeninfo only returns an email when those two
// scopes were consented. cloud-platform is required by gcloud itself.
var Mandatory = []string{
	"openid",
	Prefix + "userinfo.email",
	Prefix + "cloud-platform",
}

var short = map[string]string{
	"openid":                   "openid",
	"email":                    Prefix + "userinfo.email",
	"profile":                  Prefix + "userinfo.profile",
	"userinfo.email":           Prefix + "userinfo.email",
	"userinfo.profile":         Prefix + "userinfo.profile",
	"cloud-platform":           Prefix + "cloud-platform",
	"cloud-platform.read-only": Prefix + "cloud-platform.read-only",
	"bigquery":                 Prefix + "bigquery",
	"bigquery.readonly":        Prefix + "bigquery.readonly",
	"drive":                    Prefix + "drive",
	"drive.readonly":           Prefix + "drive.readonly",
	"drive.file":               Prefix + "drive.file",
	"sheets":                   Prefix + "spreadsheets",
	"spreadsheets":             Prefix + "spreadsheets",
	"spreadsheets.readonly":    Prefix + "spreadsheets.readonly",
	"iam.test":                 Prefix + "iam.test",
	"compute":                  Prefix + "compute",
	"storage":                  Prefix + "devstorage.read_write",
	"storage.readonly":         Prefix + "devstorage.read_only",
	"calendar":                 Prefix + "calendar",
	"gmail.readonly":           Prefix + "gmail.readonly",
	"accounts.reauth":          Prefix + "accounts.reauth",
	"sqlservice.login":         Prefix + "sqlservice.login",
}

// Presets are named scope bundles. Values use short names; Normalize expands.
var Presets = map[string][]string{
	"base":   {"openid", "email", "cloud-platform"},
	"dbt":    {"openid", "email", "cloud-platform", "bigquery", "drive", "iam.test"},
	"sheets": {"openid", "email", "cloud-platform", "bigquery", "drive", "sheets"},
	"full":   {"openid", "email", "cloud-platform", "bigquery", "drive", "sheets", "iam.test", "storage"},
}

// implies maps a broad scope to the narrower scopes it subsumes. Without this
// every identity minted with cloud-platform would report a false scope gap
// against a bigquery requirement.
var implies = map[string][]string{
	Prefix + "cloud-platform": {
		Prefix + "bigquery",
		Prefix + "bigquery.readonly",
		Prefix + "cloud-platform.read-only",
		Prefix + "compute",
		Prefix + "devstorage.read_write",
		Prefix + "devstorage.read_only",
		Prefix + "sqlservice.login",
	},
	Prefix + "bigquery":       {Prefix + "bigquery.readonly"},
	Prefix + "drive":          {Prefix + "drive.readonly", Prefix + "drive.file", Prefix + "drive.metadata.readonly"},
	Prefix + "drive.readonly": {Prefix + "drive.metadata.readonly"},
	Prefix + "spreadsheets":   {Prefix + "spreadsheets.readonly"},
	Prefix + "userinfo.email": {"email"},
}

// PresetNames returns preset keys in sorted order.
func PresetNames() []string {
	out := make([]string, 0, len(Presets))
	for k := range Presets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Expand turns a short name into a full scope URL. Already-qualified scopes
// pass through untouched.
func Expand(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if v, ok := short[s]; ok {
		return v
	}
	if strings.Contains(s, "://") || s == "openid" {
		return s
	}
	return Prefix + s
}

// Short renders a scope URL in its compact display form.
func Short(s string) string {
	if s == "openid" {
		return "openid"
	}
	if t := strings.TrimPrefix(s, Prefix); t != s {
		return t
	}
	return s
}

// ShortAll renders a list of scope URLs compactly.
func ShortAll(list []string) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, Short(s))
	}
	return out
}

// Parse splits a comma or space separated scope list.
func Parse(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(f))
	for _, v := range f {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ResolvePreset expands a named preset.
func ResolvePreset(name string) ([]string, error) {
	v, ok := Presets[name]
	if !ok {
		return nil, fmt.Errorf("unknown preset %q (have: %s)", name, strings.Join(PresetNames(), ", "))
	}
	return Normalize(v), nil
}

// Normalize expands short names, injects the mandatory set, dedupes and sorts.
func Normalize(list []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = Expand(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range Mandatory {
		add(s)
	}
	for _, s := range list {
		add(s)
	}
	sort.Strings(out)
	return out
}

// Sorted expands, dedupes and sorts without injecting the mandatory set.
//
// Recording what a credential actually holds and requesting what a new mint
// should carry are different jobs. Normalize is for the request; Sorted is for
// the record. Using Normalize to record would invent a permanent scope gap on
// every adopted credential that predates the mandatory set.
func Sorted(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range list {
		s = Expand(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// CanSelfIdentify reports whether a granted set lets tokeninfo return an
// email. Without it a credential works for API calls but cannot say who it is,
// which makes an inventory of many credentials unmaintainable.
func CanSelfIdentify(granted []string) bool {
	for _, g := range granted {
		if Expand(g) == Prefix+"userinfo.email" {
			return true
		}
	}
	return false
}

// Union merges two scope lists, normalizing the result.
func Union(a, b []string) []string {
	return Normalize(append(append([]string{}, a...), b...))
}

// Satisfies reports whether the granted set covers one required scope,
// directly or by implication.
func Satisfies(granted []string, required string) bool {
	required = Expand(required)
	for _, g := range granted {
		g = Expand(g)
		if g == required {
			return true
		}
		for _, sub := range implies[g] {
			if sub == required {
				return true
			}
		}
	}
	return false
}

// Missing returns required scopes the granted set does not cover.
func Missing(required, granted []string) []string {
	var out []string
	for _, r := range required {
		if !Satisfies(granted, r) {
			out = append(out, Expand(r))
		}
	}
	sort.Strings(out)
	return out
}

// WeakDrive reports a credential holding only drive.file. That scope grants
// access solely to files this OAuth client itself created, so it silently
// fails on an existing Sheet even though "a drive scope" appears present.
func WeakDrive(granted []string) bool {
	hasFile, hasReal := false, false
	for _, g := range granted {
		switch Expand(g) {
		case Prefix + "drive.file":
			hasFile = true
		case Prefix + "drive", Prefix + "drive.readonly":
			hasReal = true
		}
	}
	return hasFile && !hasReal
}

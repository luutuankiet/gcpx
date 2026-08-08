package cli

import (
	"strings"
	"testing"

	"github.com/luutuankiet/gcpx/internal/store"
)

// An inherited credential variable must lose to the one gcpx injects,
// otherwise a shell that already exported a different identity silently wins.
func TestMergeEnvOverridesParent(t *testing.T) {
	parent := []string{"PATH=/bin", "GOOGLE_APPLICATION_CREDENTIALS=/stale/path.json"}
	got := mergeEnv(parent, []string{"GOOGLE_APPLICATION_CREDENTIALS=/fresh/path.json"})
	var seen int
	for _, e := range got {
		if strings.HasPrefix(e, "GOOGLE_APPLICATION_CREDENTIALS=") {
			seen++
			if e != "GOOGLE_APPLICATION_CREDENTIALS=/fresh/path.json" {
				t.Errorf("stale value survived: %s", e)
			}
		}
	}
	if seen != 1 {
		t.Errorf("variable appears %d times, want exactly 1", seen)
	}
}

// gcloud reads the override variable and the client libraries read
// GOOGLE_APPLICATION_CREDENTIALS. Setting only one produces a setup that works
// in half the tools, so both are asserted.
func TestEnvForSetsBothCredentialVars(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GCPX_HOME", dir)
	id := store.Identity{Alias: "work", DefaultProject: "acme-analytics"}
	env, err := envFor(id, "", false)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		m[k] = v
	}
	if m["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"] == "" {
		t.Error("gcloud would not see a credential")
	}
	if m["GOOGLE_APPLICATION_CREDENTIALS"] != m["CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"] {
		t.Error("the CLI and the client libraries must point at the same file")
	}
	if m["CLOUDSDK_CORE_PROJECT"] != "acme-analytics" {
		t.Errorf("project not pinned: %q", m["CLOUDSDK_CORE_PROJECT"])
	}
	if _, ok := m["CLOUDSDK_CONFIG"]; ok {
		t.Error("config isolation was disabled but CLOUDSDK_CONFIG was still set")
	}
}

func TestEnvForProjectOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GCPX_HOME", dir)
	id := store.Identity{Alias: "work", DefaultProject: "acme-analytics"}
	env, err := envFor(id, "other-proj", true)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "CLOUDSDK_CORE_PROJECT=other-proj") {
		t.Errorf("per-invocation project did not win:\n%s", joined)
	}
	if !strings.Contains(joined, "CLOUDSDK_CONFIG=") {
		t.Error("config isolation requested but not applied")
	}
}

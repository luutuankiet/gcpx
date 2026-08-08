package cli

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"

	"github.com/luutuankiet/gcpx/internal/health"
	"github.com/luutuankiet/gcpx/internal/store"
)

// envFor builds the credential environment for one identity.
//
// Two variables carry the credential because gcloud and the client libraries
// read different ones: the CLI honours CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE
// and ignores GOOGLE_APPLICATION_CREDENTIALS, while the SDKs do the reverse.
// Setting only one produces a setup that works in exactly half the tools.
func envFor(id store.Identity, project string, isolate bool) ([]string, error) {
	adc := store.ADCPath(id.Alias)
	if project == "" {
		project = id.DefaultProject
	}
	kv := map[string]string{
		"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": adc,
		"GOOGLE_APPLICATION_CREDENTIALS":         adc,
		"GCPX_ALIAS":                             id.Alias,
	}
	if project != "" {
		kv["CLOUDSDK_CORE_PROJECT"] = project
		kv["GOOGLE_CLOUD_PROJECT"] = project
		kv["GCLOUD_PROJECT"] = project
	}
	if isolate {
		dir, err := store.EnsureConfigDir(id.Alias, project)
		if err != nil {
			return nil, err
		}
		kv["CLOUDSDK_CONFIG"] = dir
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+kv[k])
	}
	return out, nil
}

// mergeEnv overlays overrides onto the parent environment, replacing rather
// than appending so a stale value inherited from the shell cannot win.
func mergeEnv(parent, overrides []string) []string {
	idx := map[string]int{}
	out := append([]string{}, parent...)
	for i, e := range out {
		if k, _, ok := strings.Cut(e, "="); ok {
			idx[k] = i
		}
	}
	for _, o := range overrides {
		k, _, _ := strings.Cut(o, "=")
		if i, ok := idx[k]; ok {
			out[i] = o
		} else {
			out = append(out, o)
		}
	}
	return out
}

func isolateDefault() bool {
	return os.Getenv("GCPX_NO_ISOLATE") == ""
}

// warnIfUnhealthy surfaces a known-bad credential before a command runs,
// turning an opaque downstream API error into a named problem with a fix.
func warnIfUnhealthy(id store.Identity) {
	switch health.Display(id) {
	case store.StateExpired:
		warnf("identity %q was last seen EXPIRED. Fix: %s", id.Alias, health.CachedNextAction(id))
	case store.StateScopeGap:
		warnf("identity %q was last seen SCOPE-GAP. Fix: %s", id.Alias, health.CachedNextAction(id))
	}
}

func cmdExec(args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errf("usage: gcpx exec <alias> [-p PROJECT] -- <command> [args...]")
	}
	alias := args[0]
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var project string
	fs.StringVar(&project, "p", "", "project to pin for this invocation")
	fs.StringVar(&project, "project", "", "project to pin for this invocation")
	noIsolate := fs.Bool("no-isolate", false, "share the ambient gcloud config dir instead of a per-identity one")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return errf("nothing to run. Put the command after --, e.g. gcpx exec %s -- gcloud auth print-access-token", alias)
	}

	id, err := store.Load(alias)
	if err != nil {
		return errf("%v", err)
	}
	warnIfUnhealthy(id)

	if project != "" && len(id.KnownProjects) > 0 {
		known := false
		for _, p := range id.KnownProjects {
			if p == project {
				known = true
				break
			}
		}
		if !known {
			warnf("project %q is not in the recorded project list for %q; continuing anyway", project, alias)
		}
	}

	overrides, err := envFor(id, project, isolateDefault() && !*noIsolate)
	if err != nil {
		return errf("%v", err)
	}
	env := mergeEnv(os.Environ(), overrides)

	bin, err := exec.LookPath(rest[0])
	if err != nil {
		return errf("%v", err)
	}
	// Replacing this process rather than forking keeps exit codes, signals and
	// terminal control exactly as the caller expects.
	if err := syscall.Exec(bin, rest, env); err != nil {
		return errf("exec %s: %v", bin, err)
	}
	return 0
}

func cmdEnv(args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errf("usage: gcpx env <alias> [-p PROJECT] [--json|--export]")
	}
	alias := args[0]
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var project string
	fs.StringVar(&project, "p", "", "project to pin")
	fs.StringVar(&project, "project", "", "project to pin")
	asJSON := fs.Bool("json", false, "emit a JSON object")
	asExport := fs.Bool("export", false, "prefix each line with export")
	noIsolate := fs.Bool("no-isolate", false, "share the ambient gcloud config dir")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	id, err := store.Load(alias)
	if err != nil {
		return errf("%v", err)
	}
	overrides, err := envFor(id, project, isolateDefault() && !*noIsolate)
	if err != nil {
		return errf("%v", err)
	}
	if *asJSON {
		m := map[string]string{}
		for _, e := range overrides {
			k, v, _ := strings.Cut(e, "=")
			m[k] = v
		}
		return emitJSON(m)
	}
	for _, e := range overrides {
		if *asExport {
			k, v, _ := strings.Cut(e, "=")
			fmt.Printf("export %s=%q\n", k, v)
		} else {
			fmt.Println(e)
		}
	}
	return 0
}

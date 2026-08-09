// Package cli implements the gcpx command surface.
package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/luutuankiet/gcpx/internal/scopes"
)

// Version is stamped at build time from main.
var Version = "dev"

var usageLines = []string{
	"gcpx - per-command Google Cloud identity selection",
	"",
	"USAGE",
	"  gcpx <command> [flags]",
	"",
	"RUNNING THINGS",
	"  exec <alias> [-p PROJECT] -- <cmd...>   run a command as that identity",
	"  env <alias> [-p PROJECT] [--json]       print the environment instead of running",
	"",
	"INSPECTING",
	"  ls [--json] [--all]                     identities, states, next actions",
	"  doctor [alias|--all] [--json]           live probe + which credential source wins here",
	"  refresh [alias|--all] [--quiet]         warm tokens, update cached state",
	"",
	"ONBOARDING",
	"  login [--alias A] [--preset P] [--scopes S] [--project X] [--sdk-client]",
	"  rescope <alias> [--add S] [--set S] [--preset P] [--sdk-client]",
	"  set <alias> [--project P] [--quota-project P]   edit defaults, no re-consent",
	"  adopt --alias A --file PATH             import an existing credential file",
	"  adopt --scan                            list credential files found on this host",
	"",
	"  --sdk-client mints through 'gcloud auth login' instead of the",
	"  application-default flow. Different OAuth client, fixed scope set, and the",
	"  one that still works when a Workspace tenant blocks Drive consent.",
	"",
	"LIFECYCLE",
	"  archive <alias>                         retire, keep for audit, free the alias",
	"  rm <alias>                              delete outright",
	"  export <alias> [--out FILE]             sealed bundle for another host",
	"  import --bundle FILE [--alias A]        install a sealed bundle",
	"  push <alias> [--to h1,h2] [--dry-run]   send this credential to other hosts",
	"  fleet [ls|discover|self <name>|add|rm]  peers that mirror these identities",
	"",
	"  Consent is granted per account, not per machine: re-consenting anywhere",
	"  supersedes the credential everywhere. push re-syncs the fleet in one step,",
	"  and login/rescope/adopt offer to run it for you.",
	"",
	"BACKGROUND",
	"  schedule install|uninstall|status|print [--interval CRON]",
	"",
	"MISC",
	"  self-update [--check]",
	"  version",
	"  help [scopes]",
	"",
	"Scopes accept short names (drive, bigquery, sheets) or full URLs.",
	"Exit codes: 0 ok, 1 error, 2 scope-gap, 3 expired.",
	"",
}

func printUsage() {
	fmt.Fprintln(os.Stdout, strings.Join(usageLines, "\n"))
}

func printScopeHelp() {
	fmt.Fprintln(os.Stdout, "PRESETS")
	w := table()
	for _, n := range scopes.PresetNames() {
		fmt.Fprintf(w, "  %s\t%s\n", n, strings.Join(scopes.Presets[n], ", "))
	}
	w.Flush()
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintln(os.Stdout, "Every mint also force-includes openid, userinfo.email and cloud-platform.")
	fmt.Fprintln(os.Stdout, "openid + userinfo.email are what let tokeninfo report an email, which is the")
	fmt.Fprintln(os.Stdout, "only way a credential can identify itself. cloud-platform is required by gcloud.")
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintln(os.Stdout, "drive.file is NOT a substitute for drive: it grants access only to files this")
	fmt.Fprintln(os.Stdout, "OAuth client created, so it fails silently on a pre-existing Sheet.")
}

// Run dispatches a command and returns a process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 0
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "exec":
		return cmdExec(rest)
	case "env":
		return cmdEnv(rest)
	case "ls", "list", "status":
		return cmdLs(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "refresh":
		return cmdRefresh(rest)
	case "login":
		return cmdLogin(rest)
	case "rescope":
		return cmdRescope(rest)
	case "set":
		return cmdSet(rest)
	case "adopt":
		return cmdAdopt(rest)
	case "archive":
		return cmdArchive(rest)
	case "rm", "remove":
		return cmdRm(rest)
	case "export":
		return cmdExport(rest)
	case "import":
		return cmdImport(rest)
	case "push":
		return cmdPush(rest)
	case "fleet":
		return cmdFleet(rest)
	case "schedule":
		return cmdSchedule(rest)
	case "self-update":
		return cmdSelfUpdate(rest)
	case "version", "--version", "-v":
		fmt.Println("gcpx " + Version)
		return 0
	case "help", "--help", "-h":
		if len(rest) > 0 && rest[0] == "scopes" {
			printScopeHelp()
			return 0
		}
		printUsage()
		return 0
	default:
		return errf("unknown command %q (try: gcpx help)", cmd)
	}
}

// errf prints to stderr and yields the generic failure exit code.
func errf(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "gcpx: "+format+"\n", a...)
	return 1
}

func warnf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "gcpx: "+format+"\n", a...)
}

func table() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

func emitJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return errf("%v", err)
	}
	return 0
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// ask reads one line. A non-interactive stdin is a hard error naming the flag
// that would have supplied the value, because an agent that hangs on an
// invisible prompt is far worse than one that fails loudly.
func ask(prompt, flagName string) (string, error) {
	if !isTTY() {
		return "", fmt.Errorf("stdin is not a terminal; pass %s instead of relying on the prompt", flagName)
	}
	fmt.Fprint(os.Stderr, prompt)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func askDefault(prompt, def, flagName string) (string, error) {
	p := prompt
	if def != "" {
		p = fmt.Sprintf("%s [%s]: ", strings.TrimSuffix(prompt, ": "), def)
	}
	v, err := ask(p, flagName)
	if err != nil {
		return "", err
	}
	if v == "" {
		return def, nil
	}
	return v, nil
}

// askSecret reads a line with terminal echo disabled. stty is shelled out to
// rather than pulled in as a dependency; the fallback is a visible prompt with
// an explicit warning rather than a silent downgrade.
func askSecret(prompt string) (string, error) {
	if v := os.Getenv("GCPX_PASSPHRASE"); v != "" {
		return v, nil
	}
	if !isTTY() {
		return "", fmt.Errorf("stdin is not a terminal; set GCPX_PASSPHRASE instead")
	}
	restore := func() {}
	if _, err := exec.LookPath("stty"); err == nil {
		c := exec.Command("stty", "-echo")
		c.Stdin = os.Stdin
		if c.Run() == nil {
			restore = func() {
				r := exec.Command("stty", "echo")
				r.Stdin = os.Stdin
				_ = r.Run()
				fmt.Fprintln(os.Stderr)
			}
		} else {
			warnf("could not disable terminal echo; passphrase will be visible")
		}
	}
	defer restore()
	fmt.Fprint(os.Stderr, prompt)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func joinShort(list []string, max int) string {
	s := scopes.ShortAll(list)
	sort.Strings(s)
	if max > 0 && len(s) > max {
		return strings.Join(s[:max], ",") + fmt.Sprintf(",+%d", len(s)-max)
	}
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ",")
}

// driveScope is the full-access Drive scope. BigQuery federation to a Sheet
// authenticates with this one, not with the Sheets scope, which is the detail
// that makes "add sheets" the wrong fix for a failing dbt model.
const driveScope = "https://www.googleapis.com/auth/drive"

func hasScope(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

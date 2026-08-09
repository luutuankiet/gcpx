package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/luutuankiet/gcpx/internal/store"
)

// fleetPath is where the list of hosts mirroring this machine's identities
// lives. It holds ssh destinations and nothing else, so it is ordinary config
// rather than part of the credential store.
func fleetPath() string { return filepath.Join(store.DataDir(), "fleet.json") }

// fleetFile is deliberately per-host and self-contained. There is no
// coordinating node: each machine records who it can reach and what the others
// call it, which is the only state a peer-to-peer copy actually needs.
type fleetFile struct {
	Self  string   `json:"self,omitempty"`
	Hosts []string `json:"hosts"`
}

func loadFleetFile() fleetFile {
	var f fleetFile
	raw, err := os.ReadFile(fleetPath())
	if err != nil {
		return f
	}
	if json.Unmarshal(raw, &f) != nil {
		return fleetFile{}
	}
	return f
}

func loadFleet() []string { return loadFleetFile().Hosts }

func saveFleet(f fleetFile) error {
	if err := store.EnsureDirs(); err != nil {
		return err
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(fleetPath(), append(out, '\n'), 0o600)
}

func hasString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func splitHosts(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// otherHosts drops this machine from a target list.
//
// Hostnames are close to useless for this. An ssh destination is a human's
// name for a box and routinely bears no relation to what the box calls itself,
// so the machine's own name in the mesh is recorded explicitly and the
// hostname is only a fallback for when the two happen to agree.
func otherHosts(list []string) []string {
	self := loadFleetFile().Self
	host, _ := os.Hostname()
	if i := strings.IndexByte(host, '.'); i > 0 {
		host = host[:i]
	}
	var out []string
	for _, h := range list {
		if h == self || (self == "" && h == host) {
			continue
		}
		out = append(out, h)
	}
	return out
}

// sshConfigHosts reads plain Host entries out of the user's ssh config.
//
// Discovery reuses what the operator already maintains rather than asking them
// to restate it. Patterns and negations are skipped: a wildcard is not a
// machine anyone can push to.
func sshConfigHosts() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || !strings.EqualFold(fields[0], "host") {
			continue
		}
		for _, h := range fields[1:] {
			if strings.ContainsAny(h, "*?!") || hasString(out, h) {
				continue
			}
			out = append(out, h)
		}
	}
	return out
}

// discoverPeers probes candidates for a working gcpx and returns the ones that
// answer. Probes run concurrently because an unreachable host costs the full
// connect timeout and a serial sweep of a stale ssh config takes minutes.
func discoverPeers(candidates []string) []string {
	type result struct {
		host string
		ok   bool
	}
	ch := make(chan result, len(candidates))
	for _, h := range candidates {
		go func(h string) {
			cmd := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", h,
				`export PATH="$HOME/.local/bin:$PATH"; exec gcpx version`)
			out, err := cmd.Output()
			ch <- result{h, err == nil && strings.HasPrefix(strings.TrimSpace(string(out)), "gcpx")}
		}(h)
	}
	found := map[string]bool{}
	for range candidates {
		r := <-ch
		if r.ok {
			found[r.host] = true
		}
	}
	var out []string
	for _, h := range candidates {
		if found[h] {
			out = append(out, h)
		}
	}
	return out
}

func cmdFleet(args []string) int {
	f := loadFleetFile()
	if len(args) == 0 || args[0] == "ls" || args[0] == "list" {
		if len(f.Hosts) == 0 {
			fmt.Println("No peers known. Find them with: gcpx fleet discover")
			return 0
		}
		w := table()
		for _, h := range f.Hosts {
			mark := ""
			if len(otherHosts([]string{h})) == 0 {
				mark = "this host"
			}
			fmt.Fprintf(w, "%s\t%s\n", h, mark)
		}
		w.Flush()
		if f.Self == "" {
			warnf("this host has no name in the mesh, so push would try to ssh to itself. Fix: gcpx fleet self <name the others use for this box>")
		}
		return 0
	}
	switch args[0] {
	case "self":
		if len(args) < 2 {
			return errf("usage: gcpx fleet self <ssh-name-of-this-host>")
		}
		f.Self = args[1]
		if !hasString(f.Hosts, f.Self) {
			f.Hosts = append(f.Hosts, f.Self)
		}
	case "discover":
		candidates := sshConfigHosts()
		if len(candidates) == 0 {
			return errf("no Host entries in ~/.ssh/config to probe; add peers by name with 'gcpx fleet add'")
		}
		fmt.Fprintf(os.Stderr, "probing %d ssh destination(s) for gcpx...\n", len(candidates))
		found := discoverPeers(candidates)
		if len(found) == 0 {
			return errf("none of the %d destinations answered with a gcpx", len(candidates))
		}
		for _, h := range found {
			if !hasString(f.Hosts, h) {
				f.Hosts = append(f.Hosts, h)
			}
		}
	case "add":
		if len(args) < 2 {
			return errf("usage: gcpx fleet add <ssh-host>...")
		}
		for _, h := range args[1:] {
			if !hasString(f.Hosts, h) {
				f.Hosts = append(f.Hosts, h)
			}
		}
	case "rm", "remove":
		if len(args) < 2 {
			return errf("usage: gcpx fleet rm <ssh-host>...")
		}
		var keep []string
		for _, h := range f.Hosts {
			if !hasString(args[1:], h) {
				keep = append(keep, h)
			}
		}
		f.Hosts = keep
		if hasString(args[1:], f.Self) {
			f.Self = ""
		}
	default:
		return errf("usage: gcpx fleet [ls | discover | self <name> | add <ssh-host> | rm <ssh-host>]")
	}
	if err := saveFleet(f); err != nil {
		return errf("%v", err)
	}
	fmt.Printf("peers: %s\n", dash(strings.Join(f.Hosts, ", ")))
	if f.Self != "" {
		fmt.Printf("this host: %s\n", f.Self)
	} else {
		warnf("set this host's own name so push can skip it: gcpx fleet self <name>")
	}
	return 0
}

// bundleFor packages one identity exactly as export does, minus the sealing.
func bundleFor(alias string) ([]byte, error) {
	id, err := store.Load(alias)
	if err != nil {
		return nil, err
	}
	raw, err := store.LoadADC(alias)
	if err != nil {
		return nil, err
	}
	tb := transportBundle{Version: 1, Identity: id, Credential: json.RawMessage(raw), ExportedAt: time.Now().UTC()}
	return json.Marshal(tb)
}

// cmdPush copies one identity's live credential to the other hosts that hold it.
//
// Consent is granted per account and OAuth client, not per machine. Approving a
// new scope set replaces the grant, and every other host still holding the
// previous token is left with a receipt for an authorization that no longer
// exists. Those hosts cannot detect this -- the file looks intact and simply
// stops working -- so propagation has to be an explicit step, and an explicit
// step nobody will take unless it costs one command.
func cmdPush(args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errf("usage: gcpx push <alias> [--to host1,host2] [--dry-run]")
	}
	alias := args[0]
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	to := fs.String("to", "", "comma-separated ssh hosts; defaults to the registered fleet")
	dry := fs.Bool("dry-run", false, "report the targets without sending anything")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}

	targets := loadFleet()
	if strings.TrimSpace(*to) != "" {
		targets = splitHosts(*to)
	}
	if len(targets) == 0 {
		return errf("no target hosts. Register them once with 'gcpx fleet add <ssh-host>', or pass --to")
	}
	hosts := otherHosts(targets)
	if len(hosts) == 0 {
		return errf("every target is this host; nothing to send")
	}

	payload, err := bundleFor(alias)
	if err != nil {
		return errf("%v", err)
	}
	if *dry {
		fmt.Printf("would push %s to: %s\n", alias, strings.Join(hosts, ", "))
		return 0
	}

	rc := 0
	for _, h := range hosts {
		out, err := pushOne(h, alias, payload)
		if err != nil {
			rc = 1
			fmt.Printf("%-14s FAILED  %s\n", h, lastLineOf(out, err))
			continue
		}
		fmt.Printf("%-14s ok      %s\n", h, lastLineOf(out, nil))
	}
	if rc != 0 {
		warnf("some hosts still hold the old grant. Re-run 'gcpx push %s' once they are reachable.", alias)
	}
	return rc
}

// pushOne streams the bundle to one host over ssh stdin.
//
// The payload is deliberately unsealed on this hop. Sealing protects a bundle
// at rest or on a channel gcpx does not control; here the channel is ssh and
// the bytes never touch disk on either end. Adding a passphrase would only
// move a secret onto a remote command line, where any local ps can read it.
func pushOne(host, alias string, payload []byte) (string, error) {
	remote := `export PATH="$HOME/.local/bin:$PATH"; exec gcpx import --bundle - --alias ` +
		shellQuote(alias) + ` --force`
	cmd := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", host, remote)
	cmd.Stdin = bytes.NewReader(payload)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return strings.TrimSpace(buf.String()), err
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func lastLineOf(out string, err error) string {
	out = strings.TrimSpace(out)
	if out == "" {
		if err != nil {
			return err.Error()
		}
		return ""
	}
	lines := strings.Split(out, "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}

// offerPush closes the propagation gap at the one moment it is visible.
//
// A fresh consent silently supersedes the same identity everywhere else, and
// the person who just approved it is the only one who knows it happened. This
// is the last instant they are still looking at the terminal.
func offerPush(alias string) {
	others := otherHosts(loadFleet())
	if len(others) == 0 {
		return
	}
	warnf("%d other host(s) hold %q and are now carrying the superseded grant: %s",
		len(others), alias, strings.Join(others, ", "))
	if !isTTY() {
		fmt.Fprintf(os.Stderr, "       propagate with:  gcpx push %s\n", alias)
		return
	}
	ans, err := ask("Push the new credential to them now? [Y/n]: ", "gcpx push "+alias)
	if err != nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "", "y", "yes":
		cmdPush([]string{alias})
	}
}

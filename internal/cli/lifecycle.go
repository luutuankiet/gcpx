package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/luutuankiet/gcpx/internal/bundle"
	"github.com/luutuankiet/gcpx/internal/scopes"
	"github.com/luutuankiet/gcpx/internal/store"
)

func cmdArchive(args []string) int {
	if len(args) == 0 {
		return errf("usage: gcpx archive <alias>")
	}
	for _, a := range args {
		if err := store.Archive(a); err != nil {
			return errf("%v", err)
		}
		fmt.Printf("Archived %s. The alias is free again; the credential is kept under %s for audit.\n", a, store.ArchiveDir())
	}
	return 0
}

func cmdRm(args []string) int {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	force := fs.Bool("force", false, "skip confirmation")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	targets := fs.Args()
	if len(targets) == 0 {
		return errf("usage: gcpx rm <alias> [--force]")
	}
	for _, a := range targets {
		if !*force {
			ans, err := ask(fmt.Sprintf("Delete %s outright? Archive keeps it for audit. [y/N]: ", a), "--force")
			if err != nil {
				return errf("%v", err)
			}
			if !strings.EqualFold(ans, "y") && !strings.EqualFold(ans, "yes") {
				fmt.Println("Skipped " + a)
				continue
			}
		}
		if err := store.Remove(a); err != nil {
			return errf("%v", err)
		}
		fmt.Println("Removed " + a)
	}
	return 0
}

// transportBundle is what crosses the wire between hosts.
type transportBundle struct {
	Version    int             `json:"version"`
	Identity   store.Identity  `json:"identity"`
	Credential json.RawMessage `json:"credential"`
	ExportedAt time.Time       `json:"exported_at"`
}

func cmdExport(args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errf("usage: gcpx export <alias> [--out FILE] [--plaintext]")
	}
	alias := args[0]
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	out := fs.String("out", "", "write to a file instead of stdout")
	plain := fs.Bool("plaintext", false, "skip encryption (never do this over a channel you do not control)")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	id, err := store.Load(alias)
	if err != nil {
		return errf("%v", err)
	}
	raw, err := store.LoadADC(alias)
	if err != nil {
		return errf("%v", err)
	}
	tb := transportBundle{Version: 1, Identity: id, Credential: json.RawMessage(raw), ExportedAt: time.Now().UTC()}
	payload, err := json.Marshal(tb)
	if err != nil {
		return errf("%v", err)
	}

	var body string
	if *plain {
		warnf("exporting %s UNENCRYPTED. This file contains a live OAuth refresh token.", alias)
		body = string(payload)
	} else {
		pass, err := askSecret("Passphrase to seal the bundle: ")
		if err != nil {
			return errf("%v", err)
		}
		if pass == "" {
			return errf("empty passphrase")
		}
		confirm := pass
		if os.Getenv("GCPX_PASSPHRASE") == "" {
			confirm, err = askSecret("Confirm passphrase: ")
			if err != nil {
				return errf("%v", err)
			}
		}
		if confirm != pass {
			return errf("passphrases did not match")
		}
		sealed, err := bundle.Seal(payload, pass)
		if err != nil {
			return errf("%v", err)
		}
		body = sealed
	}

	if *out != "" {
		if err := os.WriteFile(*out, []byte(body+"\n"), 0o600); err != nil {
			return errf("%v", err)
		}
		fmt.Fprintf(os.Stderr, "Wrote %s\n", *out)
		fmt.Fprintf(os.Stderr, "On the target host:  gcpx import --bundle %s\n", *out)
		return 0
	}
	fmt.Println(body)
	return 0
}

func cmdImport(args []string) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	file := fs.String("bundle", "", "bundle file, or - for stdin")
	alias := fs.String("alias", "", "override the alias carried in the bundle")
	force := fs.Bool("force", false, "overwrite an existing alias")
	verifyFlag := fs.Bool("verify", true, "probe the credential after installing")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *file == "" {
		return errf("usage: gcpx import --bundle FILE [--alias A]")
	}
	var data []byte
	var err error
	if *file == "-" {
		data, err = readAllStdin()
	} else {
		data, err = os.ReadFile(*file)
	}
	if err != nil {
		return errf("%v", err)
	}
	text := strings.TrimSpace(string(data))

	var payload []byte
	if strings.HasPrefix(text, "gcpx-bundle-v1:") {
		pass, err := askSecret("Passphrase: ")
		if err != nil {
			return errf("%v", err)
		}
		payload, err = bundle.Open(text, pass)
		if err != nil {
			return errf("%v", err)
		}
	} else {
		payload = []byte(text)
	}

	var tb transportBundle
	if err := json.Unmarshal(payload, &tb); err != nil {
		return errf("bundle is not readable: %v", err)
	}
	id := tb.Identity
	if *alias != "" {
		id.Alias = *alias
	}
	if err := store.ValidAlias(id.Alias); err != nil {
		return errf("%v", err)
	}
	if store.Exists(id.Alias) && !*force {
		return errf("alias %q already exists here; pass --force to overwrite or --alias to rename", id.Alias)
	}
	if err := store.SaveADC(id.Alias, tb.Credential); err != nil {
		return errf("%v", err)
	}
	if *verifyFlag {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		email, granted, _, err := verify(ctx, tb.Credential)
		if err != nil {
			warnf("imported but could not verify: %v", err)
			id.State = store.StateExpired
			id.LastError = err.Error()
		} else {
			id.Email = email
			id.Scopes = scopes.Sorted(granted)
			id.State = store.StateActive
			id.LastError = ""
			id.LastVerifiedAt = time.Now().UTC()
		}
	}
	if err := store.Save(id); err != nil {
		return errf("%v", err)
	}
	fmt.Printf("Imported %s (%s)\n", id.Alias, dash(id.Email))
	return 0
}

func readAllStdin() ([]byte, error) {
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return []byte(sb.String()), nil
}

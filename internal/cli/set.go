package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/luutuankiet/gcpx/internal/auth"
	"github.com/luutuankiet/gcpx/internal/scopes"
	"github.com/luutuankiet/gcpx/internal/store"
)

// cmdSet edits an identity's defaults without touching its consent.
//
// Everything here is local metadata, so none of it needs a browser. That
// distinction is the whole point of a separate verb: before this existed the
// only way to correct a default project was to re-mint, which threw away a
// working grant to change a string.
func cmdSet(args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errf("usage: gcpx set <alias> [--project P] [--quota-project P|auto|none] [--description D] [--tags T] [--note N]")
	}
	alias := args[0]
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	project := fs.String("project", "", "default project for this identity")
	quota := fs.String("quota-project", "", "project billed for Drive/Sheets calls; 'auto' mirrors the default project, 'none' clears it")
	desc := fs.String("description", "", "what this identity is for")
	tags := fs.String("tags", "", "comma-separated tags, replaces the existing set")
	note := fs.String("note", "", "free-text note")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	changed := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { changed[f.Name] = true })

	id, err := store.Load(alias)
	if err != nil {
		return errf("%v", err)
	}
	raw, rawErr := store.LoadADC(alias)
	clientID := ""
	if rawErr == nil {
		if adc, perr := auth.ParseADC(raw); perr == nil {
			clientID = adc.ClientID
		}
	}

	if len(changed) == 0 {
		return showSettings(id, raw, clientID)
	}

	if changed["project"] {
		id.DefaultProject = strings.TrimSpace(*project)
	}
	if changed["description"] {
		id.Description = *desc
	}
	if changed["note"] {
		id.Note = *note
	}
	if changed["tags"] {
		id.Tags = scopes.Parse(*tags)
	}

	if changed["quota-project"] {
		if rawErr != nil {
			return errf("cannot set a quota project: %v", rawErr)
		}
		target := strings.TrimSpace(*quota)
		switch target {
		case "auto":
			if id.DefaultProject == "" {
				return errf("--quota-project auto needs a default project; pass --project too")
			}
			target = id.DefaultProject
		case "none", "":
			target = ""
		}
		patched, err := auth.SetQuotaProject(raw, target)
		if err != nil {
			return errf("%v", err)
		}
		if err := store.SaveADC(alias, patched); err != nil {
			return errf("%v", err)
		}
		raw = patched
		switch {
		case target == "":
			fmt.Printf("quota project cleared on %s\n", alias)
			if auth.NeedsQuotaProject(clientID) {
				warnf("this credential came from the auth-library OAuth client, which is refused by Drive and Sheets without a quota project")
			}
		default:
			fmt.Printf("quota project set to %s on %s\n", target, alias)
			if !auth.NeedsQuotaProject(clientID) {
				fmt.Fprintln(os.Stderr, "note: this credential is from the SDK OAuth client, which is exempt from the quota-project rule. Harmless, just not required.")
			}
		}
	}

	if err := store.Save(id); err != nil {
		return errf("%v", err)
	}
	if changed["project"] {
		fmt.Printf("default project set to %s on %s\n", dash(id.DefaultProject), alias)
		if auth.NeedsQuotaProject(clientID) && auth.QuotaProject(raw) == "" && hasScope(id.Scopes, driveScope) {
			warnf("%s has drive scope but no quota project, so Drive and Sheets will still refuse it. Fix: gcpx set %s --quota-project auto", alias, alias)
		}
	}
	return 0
}

func showSettings(id store.Identity, raw []byte, clientID string) int {
	w := table()
	fmt.Fprintf(w, "alias\t%s\n", id.Alias)
	fmt.Fprintf(w, "email\t%s\n", dash(id.Email))
	fmt.Fprintf(w, "project\t%s\n", dash(id.DefaultProject))
	fmt.Fprintf(w, "quota project\t%s\n", dash(auth.QuotaProject(raw)))
	fmt.Fprintf(w, "oauth client\t%s\n", auth.ClientKind(clientID))
	fmt.Fprintf(w, "description\t%s\n", dash(id.Description))
	fmt.Fprintf(w, "tags\t%s\n", dash(strings.Join(id.Tags, ",")))
	fmt.Fprintf(w, "note\t%s\n", dash(id.Note))
	w.Flush()
	if auth.NeedsQuotaProject(clientID) && auth.QuotaProject(raw) == "" && hasScope(id.Scopes, driveScope) {
		fmt.Fprintln(os.Stderr, "")
		warnf("drive scope is present but no quota project is set, so Drive and Sheets will 403 with a message about permissions. Fix: gcpx set %s --quota-project auto", id.Alias)
	}
	return 0
}

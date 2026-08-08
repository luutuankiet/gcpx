package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/luutuankiet/gcpx/internal/health"
	"github.com/luutuankiet/gcpx/internal/store"
)

type lsRow struct {
	Alias          string    `json:"alias"`
	Email          string    `json:"email"`
	Project        string    `json:"default_project,omitempty"`
	KnownProjects  []string  `json:"known_projects,omitempty"`
	Scopes         []string  `json:"scopes"`
	Tags           []string  `json:"tags,omitempty"`
	Description    string    `json:"description,omitempty"`
	State          string    `json:"state"`
	NextAction     string    `json:"next_action"`
	LastVerifiedAt time.Time `json:"last_verified_at"`
	LastError      string    `json:"last_error,omitempty"`
}

func rowFor(id store.Identity) lsRow {
	return lsRow{
		Alias:          id.Alias,
		Email:          id.Email,
		Project:        id.DefaultProject,
		KnownProjects:  id.KnownProjects,
		Scopes:         id.Scopes,
		Tags:           id.Tags,
		Description:    id.Description,
		State:          health.Display(id),
		NextAction:     health.CachedNextAction(id),
		LastVerifiedAt: id.LastVerifiedAt,
		LastError:      id.LastError,
	}
}

func cmdLs(args []string) int {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	all := fs.Bool("all", false, "include archived identities")
	wide := fs.Bool("wide", false, "show full scope lists and descriptions")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	ids, err := store.List()
	if err != nil {
		return errf("%v", err)
	}
	if *all {
		arch, err := store.ListArchived()
		if err != nil {
			return errf("%v", err)
		}
		ids = append(ids, arch...)
	}

	if *asJSON {
		rows := make([]lsRow, 0, len(ids))
		for _, id := range ids {
			rows = append(rows, rowFor(id))
		}
		return emitJSON(rows)
	}

	if len(ids) == 0 {
		fmt.Println("No identities yet.")
		fmt.Println("")
		fmt.Println("  gcpx login                 mint a new one through the browser")
		fmt.Println("  gcpx adopt --scan          find credential files already on this host")
		return 0
	}

	w := table()
	if *wide {
		fmt.Fprintln(w, "ALIAS\tEMAIL\tPROJECT\tSCOPES\tSTATE\tVERIFIED\tNEXT ACTION\tDESCRIPTION")
	} else {
		fmt.Fprintln(w, "ALIAS\tEMAIL\tPROJECT\tSCOPES\tSTATE\tVERIFIED\tNEXT ACTION")
	}
	worst := 0
	for _, id := range ids {
		st := health.Display(id)
		if c := health.ExitCode(stateToHealth(st)); c > worst {
			worst = c
		}
		max := 3
		if *wide {
			max = 0
		}
		fields := []string{
			id.Alias,
			dash(id.Email),
			dash(id.DefaultProject),
			joinShort(id.Scopes, max),
			strings.ToUpper(st),
			ago(id.LastVerifiedAt),
			health.CachedNextAction(id),
		}
		if *wide {
			fields = append(fields, dash(id.Description))
		}
		fmt.Fprintln(w, strings.Join(fields, "\t"))
	}
	w.Flush()
	return worst
}

// stateToHealth maps a stored lifecycle state onto the health vocabulary so
// one exit-code table serves both.
func stateToHealth(s string) string {
	switch s {
	case store.StateActive:
		return health.OK
	case store.StateScopeGap:
		return health.ScopeGap
	case store.StateExpired:
		return health.Expired
	case store.StateArchived:
		return health.OK
	default:
		return health.OK
	}
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

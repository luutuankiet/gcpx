package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luutuankiet/gcpx/internal/auth"
	"github.com/luutuankiet/gcpx/internal/health"
	"github.com/luutuankiet/gcpx/internal/scopes"
	"github.com/luutuankiet/gcpx/internal/store"
)

type credSource struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Present bool   `json:"present"`
	Winner  string `json:"winner,omitempty"`
}

// sources enumerates every place a credential could be coming from on this
// host. On a machine with several overlapping mechanisms, "which of these is
// actually in effect" is the question that costs the most time to answer by
// hand.
func sources() []credSource {
	ex := func(p string) bool {
		if p == "" {
			return false
		}
		_, err := os.Stat(p)
		return err == nil
	}
	override := os.Getenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE")
	gac := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	cfg := os.Getenv("CLOUDSDK_CONFIG")
	wellKnown := auth.WellKnownADC()

	out := []credSource{
		{Name: "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", Value: override, Present: ex(override)},
		{Name: "GOOGLE_APPLICATION_CREDENTIALS", Value: gac, Present: ex(gac)},
		{Name: "CLOUDSDK_CONFIG", Value: cfg, Present: ex(cfg)},
		{Name: "well-known ADC file", Value: wellKnown, Present: ex(wellKnown)},
	}
	if h, err := os.UserHomeDir(); err == nil {
		db := filepath.Join(h, ".config", "gcloud", "credentials.db")
		if cfg != "" {
			db = filepath.Join(cfg, "credentials.db")
		}
		out = append(out, credSource{Name: "gcloud credentials.db (gcloud auth login)", Value: db, Present: ex(db)})
	}

	// gcloud reads the override and ignores GOOGLE_APPLICATION_CREDENTIALS.
	// The client libraries do the opposite. Two different winners, always.
	for i := range out {
		switch out[i].Name {
		case "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE":
			if out[i].Present {
				out[i].Winner = "gcloud + bq"
			}
		case "GOOGLE_APPLICATION_CREDENTIALS":
			if out[i].Present {
				out[i].Winner = "client libraries"
			}
		case "well-known ADC file":
			if out[i].Present && gac == "" {
				out[i].Winner = "client libraries (fallback)"
			}
		}
	}
	return out
}

type doctorReport struct {
	Version   string            `json:"gcpx_version"`
	Store     string            `json:"store"`
	Gcloud    string            `json:"gcloud,omitempty"`
	Sources   []credSource      `json:"credential_sources"`
	Cron      string            `json:"cron,omitempty"`
	Results   []health.Result   `json:"identities,omitempty"`
	Drive     map[string]string `json:"drive_probe,omitempty"`
	CheckedAt time.Time         `json:"checked_at"`
}

// probeDrive answers what a scope list cannot: whether this credential opens a
// Drive file right now. Scope, quota project and Drive's own sharing rules all
// deny with the same status code, so the only honest report is a live call.
func probeDrive(ctx context.Context, alias, token string) string {
	raw, err := store.LoadADC(alias)
	if err != nil {
		return ""
	}
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	code, body, err := auth.DriveProbe(pctx, token, auth.QuotaProject(raw))
	if err != nil {
		return "probe failed: " + err.Error()
	}
	return auth.ExplainDrive(alias, code, body)
}

func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	all := fs.Bool("all", false, "probe every identity")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	targets := fs.Args()
	ctx := context.Background()

	rep := doctorReport{Version: Version, Store: store.DataDir(), CheckedAt: time.Now().UTC(), Sources: sources()}
	if g, err := auth.GcloudPath(); err == nil {
		rep.Gcloud = g
	} else {
		rep.Gcloud = ""
	}

	var ids []store.Identity
	switch {
	case len(targets) > 0:
		for _, t := range targets {
			id, err := store.Load(t)
			if err != nil {
				return errf("%v", err)
			}
			ids = append(ids, id)
		}
	case *all:
		var err error
		ids, err = store.List()
		if err != nil {
			return errf("%v", err)
		}
	}

	worst := 0
	driveNotes := map[string]string{}
	for _, id := range ids {
		r := health.Check(ctx, id)
		health.Apply(&id, r)
		_ = store.Save(id)
		// Probed while the token is still in hand, since it is scrubbed from the
		// report immediately afterwards.
		if r.AccessToken != "" && hasScope(r.Granted, driveScope) {
			driveNotes[r.Alias] = probeDrive(ctx, r.Alias, r.AccessToken)
		}
		r.AccessToken = ""
		rep.Results = append(rep.Results, r)
		if c := health.ExitCode(r.State); c > worst {
			worst = c
		}
	}
	rep.Drive = driveNotes

	if *asJSON {
		if emitJSON(rep) != 0 {
			return 1
		}
		return worst
	}

	fmt.Printf("gcpx %s\n", Version)
	fmt.Printf("store    %s\n", rep.Store)
	if rep.Gcloud == "" {
		fmt.Printf("gcloud   NOT FOUND on PATH (login and rescope will not work)\n")
	} else {
		fmt.Printf("gcloud   %s\n", rep.Gcloud)
	}
	fmt.Println("")
	fmt.Println("CREDENTIAL SOURCES VISIBLE TO THIS SHELL")
	w := table()
	fmt.Fprintln(w, "  SOURCE\tSTATUS\tCONSUMED BY\tVALUE")
	for _, s := range sources() {
		st := "unset"
		if s.Value != "" && !s.Present {
			st = "set-but-missing"
		} else if s.Present {
			st = "present"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", s.Name, st, dash(s.Winner), dash(s.Value))
	}
	w.Flush()

	fmt.Println("")
	if ok, line, err := scheduleStatus(); err != nil {
		fmt.Printf("BACKGROUND REFRESH  unavailable: %v\n", err)
		fmt.Printf("                    Run 'gcpx refresh --all --quiet' from whatever scheduler this host has.\n")
	} else if ok {
		fmt.Printf("BACKGROUND REFRESH  installed: %s\n", line)
	} else {
		fmt.Printf("BACKGROUND REFRESH  not installed. Fix: gcpx schedule install\n")
	}

	if len(rep.Results) == 0 {
		fmt.Println("")
		fmt.Println("No identity probed. Pass an alias, or --all.")
		return worst
	}
	fmt.Println("")
	fmt.Println("IDENTITY PROBES (live refresh grant + token introspection)")
	for _, r := range rep.Results {
		fmt.Println("")
		fmt.Printf("  %s\n", r.Alias)
		fmt.Printf("    state    %s\n", strings.ToUpper(r.State))
		fmt.Printf("    email    %s\n", dash(r.Email))
		fmt.Printf("    project  %s\n", dash(r.Project))
		if raw, err := store.LoadADC(r.Alias); err == nil {
			adc, perr := auth.ParseADC(raw)
			if perr == nil {
				fmt.Printf("    client   %s\n", auth.ClientKind(adc.ClientID))
				switch {
				case adc.QuotaProjectID != "":
					fmt.Printf("    quota    %s\n", adc.QuotaProjectID)
				case auth.NeedsQuotaProject(adc.ClientID):
					fmt.Printf("    quota    NOT SET - Drive and Sheets will refuse this credential. Fix: gcpx set %s --quota-project auto\n", r.Alias)
				}
			}
		}
		if note := driveNotes[r.Alias]; note != "" {
			fmt.Printf("    drive    %s\n", note)
		}
		if len(r.Granted) > 0 {
			fmt.Printf("    granted  %s\n", strings.Join(scopes.ShortAll(r.Granted), ", "))
		}
		if len(r.Missing) > 0 {
			fmt.Printf("    missing  %s\n", strings.Join(scopes.ShortAll(r.Missing), ", "))
		}
		if r.WeakDrive {
			fmt.Printf("    warning  drive.file only: reaches files this client created, not pre-existing Sheets\n")
		}
		if r.Anonymous {
			fmt.Printf("    warning  no userinfo.email scope: this credential cannot report which account it is\n")
		}
		if r.Error != "" {
			fmt.Printf("    error    %s\n", r.Error)
		}
		fmt.Printf("    fix      %s\n", r.NextAction)
	}
	return worst
}

func cmdRefresh(args []string) int {
	fs := flag.NewFlagSet("refresh", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	all := fs.Bool("all", false, "refresh every identity")
	quiet := fs.Bool("quiet", false, "print only problems (intended for cron)")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	targets := fs.Args()
	ctx := context.Background()

	var ids []store.Identity
	if len(targets) > 0 {
		for _, t := range targets {
			id, err := store.Load(t)
			if err != nil {
				return errf("%v", err)
			}
			ids = append(ids, id)
		}
	} else if *all {
		var err error
		ids, err = store.List()
		if err != nil {
			return errf("%v", err)
		}
	} else {
		return errf("pass an alias, or --all")
	}

	var results []health.Result
	worst := 0
	for _, id := range ids {
		r := health.Check(ctx, id)
		health.Apply(&id, r)
		_ = store.Save(id)
		r.AccessToken = ""
		results = append(results, r)
		if c := health.ExitCode(r.State); c > worst {
			worst = c
		}
	}
	if *asJSON {
		if emitJSON(results) != 0 {
			return 1
		}
		return worst
	}
	stamp := time.Now().UTC().Format(time.RFC3339)
	for _, r := range results {
		if *quiet && r.State == health.OK {
			continue
		}
		fmt.Printf("%s  %-16s %-10s %s\n", stamp, r.Alias, strings.ToUpper(r.State), r.NextAction)
	}
	return worst
}

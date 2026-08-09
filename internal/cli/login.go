package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/luutuankiet/gcpx/internal/auth"
	"github.com/luutuankiet/gcpx/internal/scopes"
	"github.com/luutuankiet/gcpx/internal/store"
)

var aliasSanitize = regexp.MustCompile(`[^a-z0-9._-]+`)

func suggestAlias(email string) string {
	local, _, _ := strings.Cut(email, "@")
	s := aliasSanitize.ReplaceAllString(strings.ToLower(local), "-")
	s = strings.Trim(s, "-._")
	if s == "" {
		return ""
	}
	if store.ValidAlias(s) != nil {
		return ""
	}
	return s
}

// resolveScopes turns preset and explicit-scope flags into a normalized set.
func resolveScopes(preset, explicit string, base []string) ([]string, error) {
	switch {
	case preset != "" && explicit != "":
		p, err := scopes.ResolvePreset(preset)
		if err != nil {
			return nil, err
		}
		return scopes.Union(p, scopes.Parse(explicit)), nil
	case preset != "":
		return scopes.ResolvePreset(preset)
	case explicit != "":
		return scopes.Normalize(scopes.Parse(explicit)), nil
	case len(base) > 0:
		return scopes.Normalize(base), nil
	default:
		return scopes.ResolvePreset("base")
	}
}

// verify mints an access token and introspects it, returning the identity as
// Google actually reports it rather than as the local file claims.
func verify(ctx context.Context, raw []byte) (email string, granted []string, token string, err error) {
	adc, err := auth.ParseADC(raw)
	if err != nil {
		return "", nil, "", err
	}
	tok, _, err := auth.Refresh(ctx, adc)
	if err != nil {
		return "", nil, "", err
	}
	ti, err := auth.Introspect(ctx, tok)
	if err != nil {
		return "", nil, tok, err
	}
	return ti.Email, ti.Scopes(), tok, nil
}

func probeProjects(ctx context.Context, token string) []string {
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	ps, err := auth.ListProjects(pctx, token)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.ProjectID)
	}
	sort.Strings(out)
	return out
}

// mintResult is one completed consent flow, already introspected.
type mintResult struct {
	raw     []byte
	email   string
	granted []string
	token   string
	usedSDK bool
}

// mintAndVerify runs a consent flow and checks what Google actually granted.
//
// The fallback logic exists because a tenant-side block is invisible from
// here: gcloud reports success, and the only trace is that the Drive scope
// asked for never appears on the resulting token. That signature is specific
// enough to act on, and the SDK OAuth client is the one route that gets past
// it, so it is offered by name rather than left as a puzzle.
func mintAndVerify(ctx context.Context, want []string, useSDK bool) (mintResult, error) {
	var res mintResult
	res.usedSDK = useSDK

	var raw []byte
	var err error
	if useSDK {
		fmt.Fprintf(os.Stderr, "Minting through the SDK OAuth client (gcloud auth login).\n")
		fmt.Fprintf(os.Stderr, "Scopes are fixed on this route: %s\n\n", strings.Join(scopes.ShortAll(auth.SDKLoginScopes), ", "))
		raw, err = auth.MintSDK(ctx, os.Stdin, os.Stderr)
	} else {
		fmt.Fprintf(os.Stderr, "Requesting scopes: %s\n\n", strings.Join(scopes.ShortAll(want), ", "))
		raw, err = auth.Mint(ctx, want, os.Stdin, os.Stderr)
	}
	if err != nil {
		if !useSDK && hasScope(want, driveScope) {
			warnf("the application-default consent flow failed while asking for Drive. Some Workspace tenants block that OAuth client for Drive specifically. Retry with --sdk-client to mint through 'gcloud auth login' instead.")
		}
		return res, err
	}
	res.raw = raw
	res.email, res.granted, res.token, err = verify(ctx, raw)
	if err != nil {
		return res, fmt.Errorf("minted credential failed verification: %w", err)
	}

	if !useSDK && hasScope(want, driveScope) && !hasScope(res.granted, driveScope) {
		warnf("Drive was requested but not granted. That is the signature of a Workspace tenant blocking this OAuth client's Drive consent screen, not of a wrong scope name.")
		if isTTY() {
			ans, aerr := ask("Retry through the SDK OAuth client now? [y/N]: ", "--sdk-client")
			if aerr == nil && strings.EqualFold(strings.TrimSpace(ans), "y") {
				return mintAndVerify(ctx, want, true)
			}
		} else {
			warnf("re-run with --sdk-client to take the route that is usually still permitted")
		}
	}
	return res, nil
}

// stampQuotaProject attaches a quota project to freshly minted credentials
// that need one.
//
// Doing it at mint time closes an entire class of later failure: without it,
// the first Drive or Sheets call returns a 403 whose text reads like a
// permissions problem, sending the reader to the IAM console for something
// that was only ever a missing line in a local file.
func stampQuotaProject(raw []byte, project string) ([]byte, string) {
	if project == "" {
		return raw, ""
	}
	adc, err := auth.ParseADC(raw)
	if err != nil || !auth.NeedsQuotaProject(adc.ClientID) || adc.QuotaProjectID != "" {
		return raw, adc.QuotaProjectID
	}
	patched, err := auth.SetQuotaProject(raw, project)
	if err != nil {
		return raw, ""
	}
	return patched, project
}

func cmdLogin(args []string) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	alias := fs.String("alias", "", "alias to create or re-mint")
	preset := fs.String("preset", "", "scope preset (see: gcpx help scopes)")
	scopeList := fs.String("scopes", "", "comma-separated scopes, short names allowed")
	project := fs.String("project", "", "default project for this identity")
	desc := fs.String("description", "", "free text describing what this identity is for")
	tags := fs.String("tags", "", "comma-separated tags")
	yes := fs.Bool("yes", false, "accept defaults instead of prompting")
	sdkClient := fs.Bool("sdk-client", false, "mint via 'gcloud auth login' (different OAuth client, fixed scopes, survives Drive consent blocks)")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	ctx := context.Background()

	var prior store.Identity
	havePrior := false
	if *alias != "" && store.Exists(*alias) {
		if p, err := store.Load(*alias); err == nil {
			prior, havePrior = p, true
		}
	}

	var base []string
	if havePrior {
		base = prior.Scopes
	}
	want, err := resolveScopes(*preset, *scopeList, base)
	if err != nil {
		return errf("%v", err)
	}

	res, err := mintAndVerify(ctx, want, *sdkClient)
	if err != nil {
		return errf("%v", err)
	}
	raw, email, granted, token := res.raw, res.email, res.granted, res.token
	fmt.Fprintf(os.Stderr, "\n  identity  %s\n", dash(email))
	fmt.Fprintf(os.Stderr, "  granted   %s\n", strings.Join(scopes.ShortAll(granted), ", "))
	if missing := scopes.Missing(want, granted); len(missing) > 0 {
		warnf("consent did not include: %s", strings.Join(scopes.ShortAll(missing), ", "))
	}
	if scopes.WeakDrive(granted) {
		warnf("only drive.file was granted. That scope reaches files this OAuth client created, not pre-existing Sheets.")
	}

	projects := probeProjects(ctx, token)
	if len(projects) > 0 {
		fmt.Fprintf(os.Stderr, "  projects  %d visible\n", len(projects))
	}
	fmt.Fprintln(os.Stderr, "")

	finalAlias := *alias
	if finalAlias == "" {
		suggested := suggestAlias(email)
		if *yes {
			finalAlias = suggested
		} else {
			v, err := askDefault("Alias: ", suggested, "--alias")
			if err != nil {
				return errf("%v", err)
			}
			finalAlias = v
		}
	}
	if finalAlias == "" {
		return errf("no alias chosen; pass --alias")
	}
	if err := store.ValidAlias(finalAlias); err != nil {
		return errf("%v", err)
	}

	finalProject := *project
	if finalProject == "" {
		def := prior.DefaultProject
		if def == "" && len(projects) == 1 {
			def = projects[0]
		}
		if !*yes {
			v, err := askDefault("Default project: ", def, "--project")
			if err != nil {
				return errf("%v", err)
			}
			finalProject = v
		} else {
			finalProject = def
		}
	}
	if finalProject != "" && len(projects) > 0 {
		seen := false
		for _, p := range projects {
			if p == finalProject {
				seen = true
				break
			}
		}
		if !seen {
			warnf("project %q was not in the visible project list. Resource Manager access is often restricted, so this is a hint, not a verdict.", finalProject)
		}
	}

	finalDesc := *desc
	if finalDesc == "" {
		if *yes {
			finalDesc = prior.Description
		} else {
			v, err := askDefault("Description: ", prior.Description, "--description")
			if err != nil {
				return errf("%v", err)
			}
			finalDesc = v
		}
	}

	raw, quota := stampQuotaProject(raw, finalProject)
	if quota != "" {
		fmt.Fprintf(os.Stderr, "  quota     %s (this OAuth client must name a project to bill Drive and Sheets calls to)\n", quota)
	}

	id := store.Identity{
		Alias:          finalAlias,
		Email:          email,
		Description:    finalDesc,
		DefaultProject: finalProject,
		KnownProjects:  projects,
		Scopes:         scopes.Sorted(granted),
		Tags:           scopes.Parse(*tags),
		MintedAt:       time.Now().UTC(),
		LastVerifiedAt: time.Now().UTC(),
		State:          store.StateActive,
	}
	if havePrior {
		id.MintedAt = time.Now().UTC()
		if len(id.Tags) == 0 {
			id.Tags = prior.Tags
		}
		if len(id.KnownProjects) == 0 {
			id.KnownProjects = prior.KnownProjects
		}
		id.Note = prior.Note
	}
	if err := store.SaveADC(finalAlias, raw); err != nil {
		return errf("%v", err)
	}
	if err := store.Save(id); err != nil {
		return errf("%v", err)
	}
	fmt.Printf("Saved %s (%s)\n", finalAlias, dash(email))
	fmt.Printf("Try:  gcpx exec %s -- gcloud auth print-access-token\n", finalAlias)
	offerPush(finalAlias)
	return 0
}

// cmdRescope re-mints an identity with a wider or different scope set.
//
// Scopes are frozen at consent time; there is no API to widen an existing
// grant. Re-minting is the only mechanism, so the command is named for what it
// actually does rather than pretending to patch.
func cmdRescope(args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errf("usage: gcpx rescope <alias> [--add SCOPES] [--set SCOPES] [--preset NAME]")
	}
	alias := args[0]
	fs := flag.NewFlagSet("rescope", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	add := fs.String("add", "", "scopes to add to the existing set")
	set := fs.String("set", "", "replace the scope set entirely")
	preset := fs.String("preset", "", "replace the scope set with a preset")
	sdkClient := fs.Bool("sdk-client", false, "mint via 'gcloud auth login' (different OAuth client, fixed scopes, survives Drive consent blocks)")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	id, err := store.Load(alias)
	if err != nil {
		return errf("%v", err)
	}
	var want []string
	switch {
	case *set != "":
		want = scopes.Normalize(scopes.Parse(*set))
	case *preset != "":
		want, err = scopes.ResolvePreset(*preset)
		if err != nil {
			return errf("%v", err)
		}
	case *add != "":
		want = scopes.Union(id.Scopes, scopes.Parse(*add))
	case *sdkClient:
		want = auth.SDKLoginScopes
	default:
		return errf("nothing to change: pass --add, --set, --preset or --sdk-client")
	}

	fmt.Fprintf(os.Stderr, "Re-minting %s. Scopes are fixed at consent, so this needs a fresh browser approval.\n", alias)

	ctx := context.Background()
	res, err := mintAndVerify(ctx, want, *sdkClient)
	if err != nil {
		return errf("%v", err)
	}
	raw, email, granted, token := res.raw, res.email, res.granted, res.token
	if id.Email != "" && email != "" && !strings.EqualFold(id.Email, email) {
		warnf("signed in as %s but %q previously held %s. Overwriting.", email, alias, id.Email)
	}
	if missing := scopes.Missing(want, granted); len(missing) > 0 {
		warnf("consent did not include: %s", strings.Join(scopes.ShortAll(missing), ", "))
	}
	id.Email = email
	id.Scopes = scopes.Sorted(granted)
	id.MintedAt = time.Now().UTC()
	id.LastVerifiedAt = time.Now().UTC()
	id.LastError = ""
	id.State = store.StateActive
	if p := probeProjects(ctx, token); len(p) > 0 {
		id.KnownProjects = p
	}
	raw, quota := stampQuotaProject(raw, id.DefaultProject)
	if quota != "" {
		fmt.Fprintf(os.Stderr, "quota project kept at %s\n", quota)
	}
	if err := store.SaveADC(alias, raw); err != nil {
		return errf("%v", err)
	}
	if err := store.Save(id); err != nil {
		return errf("%v", err)
	}
	fmt.Printf("Rescoped %s: %s\n", alias, strings.Join(scopes.ShortAll(id.Scopes), ", "))
	offerPush(alias)
	return 0
}

func cmdAdopt(args []string) int {
	fs := flag.NewFlagSet("adopt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	scan := fs.Bool("scan", false, "list credential files already present on this host")
	alias := fs.String("alias", "", "alias to file the credential under")
	file := fs.String("file", "", "path to an existing credential file")
	project := fs.String("project", "", "default project")
	desc := fs.String("description", "", "what this identity is for")
	tags := fs.String("tags", "", "comma-separated tags")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	ctx := context.Background()

	if *scan {
		return scanCredentials(ctx)
	}
	if *file == "" {
		return errf("pass --file PATH (or --scan to see what is on this host)")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return errf("%v", err)
	}
	email, granted, token, err := verify(ctx, raw)
	if err != nil {
		return errf("credential is not usable: %v", err)
	}
	finalAlias := *alias
	if finalAlias == "" {
		suggested := suggestAlias(email)
		v, err := askDefault("Alias: ", suggested, "--alias")
		if err != nil {
			return errf("%v", err)
		}
		finalAlias = v
	}
	if err := store.ValidAlias(finalAlias); err != nil {
		return errf("%v", err)
	}
	if store.Exists(finalAlias) {
		return errf("alias %q already exists; archive it first or choose another", finalAlias)
	}
	id := store.Identity{
		Alias:          finalAlias,
		Email:          email,
		Description:    *desc,
		DefaultProject: *project,
		KnownProjects:  probeProjects(ctx, token),
		Scopes:         scopes.Sorted(granted),
		Tags:           scopes.Parse(*tags),
		MintedAt:       time.Now().UTC(),
		LastVerifiedAt: time.Now().UTC(),
		State:          store.StateActive,
		Note:           "adopted from " + *file,
	}
	if scopes.WeakDrive(granted) {
		warnf("%s holds drive.file only, which cannot open pre-existing Sheets. Fix: gcpx rescope %s --add drive", finalAlias, finalAlias)
	}
	var quota string
	raw, quota = stampQuotaProject(raw, *project)
	if quota != "" {
		fmt.Fprintf(os.Stderr, "quota project set to %s (this OAuth client needs one for Drive and Sheets)\n", quota)
	}
	if !scopes.CanSelfIdentify(granted) {
		warnf("%s cannot report its own account: it was minted without userinfo.email. Usable, but it will show a blank email everywhere. Fix: gcpx rescope %s --add email", finalAlias, finalAlias)
	}
	if err := store.SaveADC(finalAlias, raw); err != nil {
		return errf("%v", err)
	}
	if err := store.Save(id); err != nil {
		return errf("%v", err)
	}
	fmt.Printf("Adopted %s (%s)\n", finalAlias, dash(email))
	offerPush(finalAlias)
	return 0
}

// scanCredentials looks for authorized_user credential files lying around and
// reports what each one actually is. Files carry no identity of their own, so
// each candidate is probed live.
func scanCredentials(ctx context.Context) int {
	var dirs []string
	if v := os.Getenv("CLOUDSDK_CONFIG"); v != "" {
		dirs = append(dirs, v)
	}
	if h, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(h, ".config", "gcloud"))
	}
	seen := map[string]bool{}
	var cands []string
	for _, d := range dirs {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(d, e.Name())
			if seen[p] {
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil || len(b) > 1<<20 {
				continue
			}
			if _, err := auth.ParseADC(b); err != nil {
				continue
			}
			seen[p] = true
			cands = append(cands, p)
		}
	}
	if len(cands) == 0 {
		fmt.Println("No authorized_user credential files found.")
		return 0
	}
	sort.Strings(cands)
	fmt.Fprintf(os.Stderr, "Probing %d credential files...\n\n", len(cands))
	w := table()
	fmt.Fprintln(w, "FILE\tEMAIL\tSCOPES\tSTATE")
	for _, p := range cands {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		email, granted, _, err := verify(cctx, b)
		cancel()
		state := "OK"
		if err != nil {
			state = "DEAD"
		}
		if scopes.WeakDrive(granted) {
			state = "OK/weak-drive"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", filepath.Base(p), dash(email), joinShort(granted, 4), state)
	}
	w.Flush()
	fmt.Println("")
	fmt.Println("Adopt one with:  gcpx adopt --alias NAME --file <full path>")
	return 0
}

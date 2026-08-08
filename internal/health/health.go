// Package health classifies a credential into one of a small set of states
// and pairs each with the literal command that fixes it.
//
// Every verdict comes from one live refresh-grant attempt. Reading the file
// tells you nothing: it has no scopes field, no expiry, and no way to know
// whether the token behind it was revoked an hour ago.
package health

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/luutuankiet/gcpx/internal/auth"
	"github.com/luutuankiet/gcpx/internal/scopes"
	"github.com/luutuankiet/gcpx/internal/store"
)

// States. Kept ASCII and lowercase so they survive grep, JSON and tabwriter
// alignment equally well.
const (
	OK       = "ok"
	ScopeGap = "scope-gap"
	Expired  = "expired"
	Unknown  = "unknown"
)

// StaleAfter is how long a verified credential stays trusted before ls calls
// it stale. Staleness is a display hint, never a verdict.
const StaleAfter = 24 * time.Hour

// Result is one credential's verdict.
type Result struct {
	Alias      string    `json:"alias"`
	Email      string    `json:"email"`
	Project    string    `json:"project,omitempty"`
	State      string    `json:"state"`
	Granted    []string  `json:"granted_scopes,omitempty"`
	Missing    []string  `json:"missing_scopes,omitempty"`
	WeakDrive  bool      `json:"weak_drive,omitempty"`
	Anonymous  bool      `json:"anonymous,omitempty"`
	Error      string    `json:"error,omitempty"`
	NextAction string    `json:"next_action"`
	CheckedAt  time.Time `json:"checked_at"`

	// AccessToken is populated on success for callers that want to reuse it
	// (project probing, for instance). Never serialized.
	AccessToken string `json:"-"`
}

// Check performs the one live probe that decides an identity's state.
func Check(ctx context.Context, id store.Identity) Result {
	r := Result{Alias: id.Alias, Email: id.Email, Project: id.DefaultProject, CheckedAt: time.Now().UTC()}

	raw, err := store.LoadADC(id.Alias)
	if err != nil {
		r.State = Expired
		r.Error = "credential file missing"
		r.NextAction = fmt.Sprintf("gcpx login --alias %s", id.Alias)
		return r
	}
	adc, err := auth.ParseADC(raw)
	if err != nil {
		r.State = Expired
		r.Error = err.Error()
		r.NextAction = fmt.Sprintf("gcpx login --alias %s", id.Alias)
		return r
	}

	tok, _, err := auth.Refresh(ctx, adc)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidGrant) {
			r.State = Expired
			r.Error = err.Error()
			r.NextAction = fmt.Sprintf("gcpx login --alias %s", id.Alias)
			return r
		}
		r.State = Unknown
		r.Error = err.Error()
		r.NextAction = fmt.Sprintf("gcpx doctor %s   # network or endpoint problem, credential not proven dead", id.Alias)
		return r
	}
	r.AccessToken = tok

	ti, err := auth.Introspect(ctx, tok)
	if err != nil {
		r.State = Unknown
		r.Error = err.Error()
		r.NextAction = fmt.Sprintf("gcpx doctor %s", id.Alias)
		return r
	}
	if ti.Email != "" {
		r.Email = ti.Email
	}
	r.Granted = ti.Scopes()
	r.WeakDrive = scopes.WeakDrive(r.Granted)

	r.Missing = scopes.Missing(id.Scopes, r.Granted)
	if len(r.Missing) > 0 {
		r.State = ScopeGap
		r.NextAction = fmt.Sprintf("gcpx rescope %s --add %s", id.Alias, strings.Join(scopes.ShortAll(r.Missing), ","))
		return r
	}

	r.State = OK
	r.NextAction = "-"
	switch {
	case r.WeakDrive:
		r.NextAction = fmt.Sprintf("gcpx rescope %s --add drive   # holds drive.file only, which cannot open pre-existing Sheets", id.Alias)
	case !scopes.CanSelfIdentify(r.Granted):
		// Usable, but anonymous. Not a failure: an advisory, because an
		// inventory of unlabelable credentials is what this tool exists to end.
		r.Anonymous = true
		r.NextAction = fmt.Sprintf("gcpx rescope %s --add email   # works, but cannot report which account it belongs to", id.Alias)
	}
	return r
}

// ExitCode maps a state to a process exit code so callers can branch without
// parsing output.
func ExitCode(state string) int {
	switch state {
	case OK:
		return 0
	case ScopeGap:
		return 2
	case Expired:
		return 3
	default:
		return 1
	}
}

// Apply folds a verdict back into stored metadata.
func Apply(id *store.Identity, r Result) {
	id.LastVerifiedAt = r.CheckedAt
	id.LastError = r.Error
	if r.Email != "" {
		id.Email = r.Email
	}
	switch r.State {
	case OK:
		id.State = store.StateActive
	case ScopeGap:
		id.State = store.StateScopeGap
	case Expired:
		id.State = store.StateExpired
	}
}

// Display renders the state shown in ls, downgrading a stale-but-unverified
// active credential so the table never overstates confidence.
func Display(id store.Identity) string {
	if id.State == store.StateActive && time.Since(id.LastVerifiedAt) > StaleAfter {
		return store.StateStale
	}
	if id.State == "" {
		return Unknown
	}
	return id.State
}

// CachedNextAction is the remediation shown by ls, which reports last known
// state rather than performing a live probe.
func CachedNextAction(id store.Identity) string {
	switch Display(id) {
	case store.StateExpired:
		return fmt.Sprintf("gcpx login --alias %s", id.Alias)
	case store.StateScopeGap:
		return fmt.Sprintf("gcpx rescope %s --add <scope>", id.Alias)
	case store.StateStale, Unknown:
		return fmt.Sprintf("gcpx refresh %s", id.Alias)
	default:
		return "-"
	}
}

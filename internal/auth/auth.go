// Package auth mints, refreshes and introspects Application Default
// Credentials.
//
// Minting shells out to gcloud rather than reimplementing the OAuth dance.
// The headless flow depends on a Google-hosted redirect page reserved for
// Google's own client, so a hand-rolled implementation would be betting on an
// undocumented endpoint for no gain.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	tokenEndpoint     = "https://oauth2.googleapis.com/token"
	tokenInfoEndpoint = "https://oauth2.googleapis.com/tokeninfo"
	projectsEndpoint  = "https://cloudresourcemanager.googleapis.com/v1/projects"
)

// ErrInvalidGrant means the refresh token is dead: revoked, expired, or the
// consent was withdrawn. It is the single unambiguous signal that an identity
// needs a fresh browser consent.
var ErrInvalidGrant = errors.New("invalid_grant")

// ADC mirrors the authorized_user credential file gcloud writes.
//
// Note what is absent: there is no scopes field, and gcloud leaves account
// empty. A credential file genuinely cannot describe its own capabilities,
// which is why introspection is mandatory and why gcpx keeps a sidecar.
type ADC struct {
	Account        string `json:"account,omitempty"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	QuotaProjectID string `json:"quota_project_id,omitempty"`
	RefreshToken   string `json:"refresh_token"`
	Type           string `json:"type"`
	UniverseDomain string `json:"universe_domain,omitempty"`
}

// ParseADC decodes and sanity-checks a credential file.
func ParseADC(raw []byte) (ADC, error) {
	var a ADC
	if err := json.Unmarshal(raw, &a); err != nil {
		return a, fmt.Errorf("not valid JSON: %w", err)
	}
	if a.Type != "" && a.Type != "authorized_user" {
		return a, fmt.Errorf("unsupported credential type %q (gcpx manages authorized_user ADC only)", a.Type)
	}
	if a.RefreshToken == "" || a.ClientID == "" || a.ClientSecret == "" {
		return a, errors.New("credential is missing client_id, client_secret or refresh_token")
	}
	return a, nil
}

var httpClient = &http.Client{Timeout: 30 * time.Second}

type tokenResp struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// Refresh exchanges the refresh token for an access token. This one call is
// the entire health check: success means the credential is alive, an
// invalid_grant means it is dead, anything else is a network problem.
func Refresh(ctx context.Context, a ADC) (string, time.Duration, error) {
	form := url.Values{
		"client_id":     {a.ClientID},
		"client_secret": {a.ClientSecret},
		"refresh_token": {a.RefreshToken},
		"grant_type":    {"refresh_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var tr tokenResp
	_ = json.Unmarshal(body, &tr)
	if resp.StatusCode != http.StatusOK {
		if tr.Error == "invalid_grant" {
			msg := tr.ErrorDesc
			if msg == "" {
				msg = "refresh token rejected"
			}
			return "", 0, fmt.Errorf("%w: %s", ErrInvalidGrant, msg)
		}
		if tr.Error != "" {
			return "", 0, fmt.Errorf("token endpoint %d: %s: %s", resp.StatusCode, tr.Error, tr.ErrorDesc)
		}
		return "", 0, fmt.Errorf("token endpoint %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if tr.AccessToken == "" {
		return "", 0, errors.New("token endpoint returned no access_token")
	}
	return tr.AccessToken, time.Duration(tr.ExpiresIn) * time.Second, nil
}

// TokenInfo is Google's introspection response.
type TokenInfo struct {
	Aud       string `json:"aud"`
	Scope     string `json:"scope"`
	Email     string `json:"email"`
	ExpiresIn string `json:"expires_in"`
	Sub       string `json:"sub"`
	Error     string `json:"error"`
	ErrorDesc string `json:"error_description"`
}

// Scopes splits the space-separated scope string.
func (t TokenInfo) Scopes() []string {
	return strings.Fields(t.Scope)
}

// Introspect asks Google what an access token can actually do. This is the
// only ground truth for scopes and identity — never trust the local file.
func Introspect(ctx context.Context, accessToken string) (TokenInfo, error) {
	var ti TokenInfo
	u := tokenInfoEndpoint + "?access_token=" + url.QueryEscape(accessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ti, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return ti, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(body, &ti); err != nil {
		return ti, fmt.Errorf("tokeninfo %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if ti.Error != "" {
		return ti, fmt.Errorf("tokeninfo: %s: %s", ti.Error, ti.ErrorDesc)
	}
	return ti, nil
}

// Project is a minimal Cloud Resource Manager project record.
type Project struct {
	ProjectID string `json:"projectId"`
	Name      string `json:"name"`
	State     string `json:"lifecycleState"`
}

// ListProjects enumerates visible projects. Best-effort: many Workspace
// policies deny resource-manager listing while still permitting BigQuery, so
// an error here is informational, never fatal.
func ListProjects(ctx context.Context, accessToken string) ([]Project, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, projectsEndpoint+"?pageSize=200", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("projects.list %d", resp.StatusCode)
	}
	var out struct {
		Projects []Project `json:"projects"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	var active []Project
	for _, p := range out.Projects {
		if p.State == "" || p.State == "ACTIVE" {
			active = append(active, p)
		}
	}
	return active, nil
}

// GcloudPath resolves the gcloud executable.
func GcloudPath() (string, error) {
	if v := os.Getenv("GCPX_GCLOUD"); v != "" {
		return v, nil
	}
	p, err := exec.LookPath("gcloud")
	if err != nil {
		return "", errors.New("gcloud not found on PATH (install the Google Cloud SDK, or set GCPX_GCLOUD)")
	}
	return p, nil
}

// Mint runs the headless browser consent flow and returns the resulting raw
// credential bytes.
//
// The critical detail is CLOUDSDK_CONFIG pointing at a throwaway directory:
// gcloud always writes to the well-known ADC path inside its config dir, so
// redirecting that dir is what keeps the caller's real credential file from
// being clobbered. That clobbering is the exact failure mode where a tool
// re-running a bare login silently strips previously consented scopes.
func Mint(ctx context.Context, scopeList []string, stdin io.Reader, progress io.Writer) ([]byte, error) {
	g, err := GcloudPath()
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "gcpx-mint-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	args := []string{
		"auth", "application-default", "login",
		"--no-launch-browser",
		"--scopes=" + strings.Join(scopeList, ","),
	}
	cmd := exec.CommandContext(ctx, g, args...)
	cmd.Env = append(os.Environ(),
		"CLOUDSDK_CONFIG="+tmp,
		"CLOUDSDK_CORE_DISABLE_PROMPTS=0",
	)
	cmd.Stdin = stdin
	// gcloud prints the consent URL and the code prompt on stdout; routing it to
	// the progress writer keeps this command's own stdout clean for --json.
	cmd.Stdout = progress
	cmd.Stderr = progress
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gcloud login failed: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(tmp, "application_default_credentials.json"))
	if err != nil {
		return nil, fmt.Errorf("gcloud reported success but wrote no credential: %w", err)
	}
	if _, err := ParseADC(raw); err != nil {
		return nil, fmt.Errorf("minted credential rejected: %w", err)
	}
	return raw, nil
}

// WellKnownADC is the path gcloud writes when nothing overrides it.
func WellKnownADC() string {
	if v := os.Getenv("CLOUDSDK_CONFIG"); v != "" {
		return filepath.Join(v, "application_default_credentials.json")
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".config", "gcloud", "application_default_credentials.json")
}

// OAuth client lineage.
//
// A credential's client_id decides two things no other field reveals: whether
// a Workspace tenant will show a Drive consent screen for it at all, and
// whether Google demands a quota project on every non-Cloud API call. Two
// credentials with byte-identical scope lists behave differently on both
// counts purely because of which command minted them.
const (
	// SDKClientPrefix is the shared Google Cloud SDK client, carried by
	// credentials from `gcloud auth login`. Exempt from the quota-project rule
	// and allowlisted by default in most Workspace tenants.
	SDKClientPrefix = "32555940559"
	// AuthLibraryClientPrefix is the client `gcloud auth application-default
	// login` uses. Subject to the quota-project rule, and some tenants block
	// its Drive consent screen outright.
	AuthLibraryClientPrefix = "764086051850"
)

// ClientKind names the OAuth client that minted a credential.
func ClientKind(clientID string) string {
	switch {
	case clientID == "":
		return "unknown"
	case strings.HasPrefix(clientID, SDKClientPrefix):
		return "sdk"
	case strings.HasPrefix(clientID, AuthLibraryClientPrefix):
		return "auth-library"
	default:
		return "custom"
	}
}

// NeedsQuotaProject reports whether Google will reject this credential's
// non-Cloud API calls until a quota project is attached. Only the SDK client
// is exempt.
func NeedsQuotaProject(clientID string) bool {
	return ClientKind(clientID) != "sdk"
}

// SDKLoginScopes is what `gcloud auth login --enable-gdrive-access` grants.
// The set is fixed: that command has no --scopes flag, so a caller taking the
// SDK route trades scope control for a consent screen that is far more likely
// to be permitted.
var SDKLoginScopes = []string{
	"openid",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/appengine.admin",
	"https://www.googleapis.com/auth/compute",
	"https://www.googleapis.com/auth/sqlservice.login",
	"https://www.googleapis.com/auth/accounts.reauth",
	"https://www.googleapis.com/auth/drive",
}

// MintSDK mints through `gcloud auth login --update-adc` rather than the
// application-default flow.
//
// Same throwaway CLOUDSDK_CONFIG discipline as Mint, for the same reason: the
// caller's real credential file must not be clobbered. The difference that
// matters is the OAuth client, which is not selectable on either command --
// choosing the command is the only way to choose the client.
func MintSDK(ctx context.Context, stdin io.Reader, progress io.Writer) ([]byte, error) {
	g, err := GcloudPath()
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "gcpx-mint-sdk-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	args := []string{
		"auth", "login",
		"--no-launch-browser",
		"--enable-gdrive-access",
		"--update-adc",
		"--brief",
	}
	cmd := exec.CommandContext(ctx, g, args...)
	cmd.Env = append(os.Environ(),
		"CLOUDSDK_CONFIG="+tmp,
		"CLOUDSDK_CORE_DISABLE_PROMPTS=0",
	)
	cmd.Stdin = stdin
	cmd.Stdout = progress
	cmd.Stderr = progress
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gcloud auth login failed: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(tmp, "application_default_credentials.json"))
	if err != nil {
		return nil, fmt.Errorf("gcloud reported success but wrote no ADC file; this gcloud may predate --update-adc: %w", err)
	}
	if _, err := ParseADC(raw); err != nil {
		return nil, fmt.Errorf("minted credential rejected: %w", err)
	}
	return raw, nil
}

// QuotaProject reads the quota project out of raw credential bytes.
func QuotaProject(raw []byte) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	s, _ := m["quota_project_id"].(string)
	return s
}

// SetQuotaProject rewrites the quota project inside raw credential bytes.
//
// Deliberately map-based rather than struct-based: Google adds fields to this
// file format without notice, and a struct round-trip would silently drop any
// field gcpx does not know about.
func SetQuotaProject(raw []byte, project string) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if project == "" {
		delete(m, "quota_project_id")
	} else {
		m["quota_project_id"] = project
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

const driveFilesEndpoint = "https://www.googleapis.com/drive/v3/files"

// DriveProbe issues the cheapest Drive call there is and returns the raw
// outcome for ExplainDrive to interpret.
//
// The quota-project header is sent explicitly because that is what a client
// library does once quota_project_id is present in the credential file. A bare
// curl never reads the credential file, so a probe without this header tests
// something no real caller experiences.
func DriveProbe(ctx context.Context, accessToken, quotaProject string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, driveFilesEndpoint+"?pageSize=1&fields=files(id)", nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	if quotaProject != "" {
		req.Header.Set("x-goog-user-project", quotaProject)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, string(b), nil
}

// ExplainDrive names which gate a Drive failure came from.
//
// Three independent systems can deny the same call -- the OAuth scope on the
// token, the quota project billed for the call, and Drive's own file sharing.
// Google answers 403 for all three with wording that reads like an IAM problem
// in every case, which is what sends people to the permissions console when
// the real fix is one line of local config.
func ExplainDrive(alias string, status int, body string) string {
	if status == http.StatusOK {
		return "ok - this credential can read Drive right now"
	}
	low := strings.ToLower(body)
	switch {
	case strings.Contains(low, "requires a quota project"):
		return fmt.Sprintf("quota-project layer, NOT scopes. This credential's OAuth client must name a project to bill Drive calls to. Fix: gcpx set %s --quota-project auto", alias)
	case strings.Contains(low, "serviceusage.services.use"), strings.Contains(low, "user_project_denied"):
		return "quota-project layer: this account may not bill against the project currently set as quota project. No local fix -- it needs roles/serviceusage.serviceUsageConsumer there, or point --quota-project at a project where it already has that."
	case strings.Contains(low, "insufficient authentication scopes"), status == http.StatusUnauthorized:
		return fmt.Sprintf("scope layer: no drive scope on this credential. Fix: gcpx rescope %s --add drive (add --sdk-client if the consent screen is blocked)", alias)
	case strings.Contains(low, "has not been used in project"), strings.Contains(low, "is disabled"):
		return "API-enablement layer: the Drive API is switched off in the quota project. Fix: enable drive.googleapis.com there."
	default:
		return fmt.Sprintf("HTTP %d: %s", status, firstLine(body))
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

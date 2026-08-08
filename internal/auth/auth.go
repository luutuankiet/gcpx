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

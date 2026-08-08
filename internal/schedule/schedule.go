// Package schedule manages the background refresh entry.
//
// crontab rather than a systemd user timer: user units are killed on logout
// unless loginctl enable-linger has been run, which needs root. gcpx installs
// itself into a home directory with no privileges, so cron is the only
// mechanism available on every host in a mixed fleet, macOS included.
package schedule

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Marker tags the managed line so install and uninstall stay idempotent
// without ever touching a user's other cron entries.
const Marker = "# gcpx-refresh"

// DefaultInterval refreshes twice an hour: often enough that a dead
// credential is noticed within one coffee break, rare enough to be invisible.
const DefaultInterval = "*/30 * * * *"

func readCrontab() (string, error) {
	cmd := exec.Command("crontab", "-l")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		// "no crontab for user" exits non-zero; that is an empty crontab, not a
		// failure.
		if strings.Contains(strings.ToLower(errb.String()), "no crontab") {
			return "", nil
		}
		if out.Len() == 0 && errb.Len() == 0 {
			return "", nil
		}
		return "", fmt.Errorf("crontab -l: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func writeCrontab(content string) error {
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("crontab -: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}

func stripManaged(content string) []string {
	var keep []string
	for _, l := range strings.Split(content, "\n") {
		if strings.Contains(l, Marker) {
			continue
		}
		keep = append(keep, l)
	}
	// trim trailing blanks
	for len(keep) > 0 && strings.TrimSpace(keep[len(keep)-1]) == "" {
		keep = keep[:len(keep)-1]
	}
	return keep
}

// Line renders the managed crontab entry.
func Line(exePath, interval, logPath string) string {
	return fmt.Sprintf("%s %s refresh --all --quiet >> %s 2>&1 %s", interval, exePath, logPath, Marker)
}

// Install adds or replaces the managed entry.
func Install(exePath, interval, logPath string) (string, error) {
	if interval == "" {
		interval = DefaultInterval
	}
	cur, err := readCrontab()
	if err != nil {
		return "", err
	}
	line := Line(exePath, interval, logPath)
	keep := append(stripManaged(cur), line)
	return line, writeCrontab(strings.Join(keep, "\n") + "\n")
}

// Uninstall removes the managed entry, leaving everything else untouched.
func Uninstall() (bool, error) {
	cur, err := readCrontab()
	if err != nil {
		return false, err
	}
	if !strings.Contains(cur, Marker) {
		return false, nil
	}
	keep := stripManaged(cur)
	body := ""
	if len(keep) > 0 {
		body = strings.Join(keep, "\n") + "\n"
	}
	return true, writeCrontab(body)
}

// Status reports whether the managed entry is installed and what it says.
func Status() (bool, string, error) {
	cur, err := readCrontab()
	if err != nil {
		return false, "", err
	}
	for _, l := range strings.Split(cur, "\n") {
		if strings.Contains(l, Marker) {
			return true, strings.TrimSpace(l), nil
		}
	}
	return false, "", nil
}

// Available reports whether a crontab binary exists at all.
func Available() bool {
	_, err := exec.LookPath("crontab")
	return err == nil
}

// SelfPath resolves this executable, preferring an absolute path so the cron
// entry keeps working under cron's minimal PATH.
func SelfPath() string {
	p, err := os.Executable()
	if err != nil {
		return "gcpx"
	}
	return p
}

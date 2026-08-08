// Package updater replaces the running binary with the latest release.
package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	defaultRepo = "luutuankiet/gcpx"
	binaryName  = "gcpx"
)

var client = &http.Client{Timeout: 120 * time.Second}

func repo() string {
	if v := os.Getenv("GCPX_REPO"); v != "" {
		return v
	}
	return defaultRepo
}

// Latest returns the newest published release tag.
func Latest(ctx context.Context) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github releases/latest: %d", resp.StatusCode)
	}
	var out struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if out.Tag == "" {
		return "", errors.New("no tag_name in release response")
	}
	return out.Tag, nil
}

func assetURL(tag, goos, goarch string) string {
	stripped := strings.TrimPrefix(tag, "v")
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/%s_%s_%s_%s.tar.gz",
		repo(), tag, binaryName, stripped, goos, goarch)
}

// Update downloads the given tag and atomically swaps the running binary.
func Update(ctx context.Context, tag string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return err
	}
	url := assetURL(tag, runtime.GOOS, runtime.GOARCH)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %d", url, resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var found bool
	// Write the replacement beside the current binary so the final rename is a
	// same-filesystem operation and therefore atomic.
	tmp, err := os.CreateTemp(filepath.Dir(exePath), "."+binaryName+".update.*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			tmp.Close()
			return err
		}
		if filepath.Base(hdr.Name) != binaryName || hdr.Typeflag != tar.TypeReg {
			continue
		}
		if _, err := io.Copy(tmp, tr); err != nil {
			tmp.Close()
			return err
		}
		found = true
		break
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("archive did not contain a %s binary", binaryName)
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}
	return os.Rename(tmpPath, exePath)
}

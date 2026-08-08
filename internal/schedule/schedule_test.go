package schedule

import (
	"strings"
	"testing"
)

// Uninstall must remove only the managed line. Eating a user's unrelated cron
// entries would be an unrecoverable mistake.
func TestStripManagedKeepsForeignLines(t *testing.T) {
	cur := strings.Join([]string{
		"0 3 * * * /usr/bin/backup",
		"*/30 * * * * /home/u/.local/bin/gcpx refresh --all --quiet >> /tmp/l 2>&1 " + Marker,
		"@reboot /usr/bin/something",
	}, "\n")
	keep := stripManaged(cur)
	if len(keep) != 2 {
		t.Fatalf("kept %d lines, want 2: %v", len(keep), keep)
	}
	for _, l := range keep {
		if strings.Contains(l, Marker) {
			t.Errorf("managed line survived: %s", l)
		}
	}
}

func TestStripManagedIsIdempotent(t *testing.T) {
	cur := "0 3 * * * /usr/bin/backup"
	if got := stripManaged(cur); len(got) != 1 || got[0] != cur {
		t.Errorf("stripManaged altered a crontab with no managed line: %v", got)
	}
}

func TestLineCarriesMarker(t *testing.T) {
	l := Line("/bin/gcpx", DefaultInterval, "/tmp/log")
	if !strings.HasSuffix(l, Marker) {
		t.Errorf("line must end with the marker so uninstall can find it: %s", l)
	}
	if !strings.Contains(l, "refresh --all --quiet") {
		t.Errorf("unexpected cron command: %s", l)
	}
}

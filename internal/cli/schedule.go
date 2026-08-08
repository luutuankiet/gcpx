package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/luutuankiet/gcpx/internal/schedule"
	"github.com/luutuankiet/gcpx/internal/store"
	"github.com/luutuankiet/gcpx/internal/updater"
)

func scheduleStatus() (bool, string, error) {
	if !schedule.Available() {
		return false, "", fmt.Errorf("crontab not available")
	}
	return schedule.Status()
}

func cmdSchedule(args []string) int {
	if len(args) == 0 {
		return errf("usage: gcpx schedule install|uninstall|status|print [--interval CRON]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("schedule", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	interval := fs.String("interval", schedule.DefaultInterval, "cron schedule expression")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	logPath := store.LogPath()
	if err := store.EnsureDirs(); err != nil {
		return errf("%v", err)
	}

	switch sub {
	case "print":
		fmt.Println(schedule.Line(schedule.SelfPath(), *interval, logPath))
		return 0
	case "status":
		ok, line, err := scheduleStatus()
		if err != nil {
			return errf("%v", err)
		}
		if !ok {
			fmt.Println("not installed")
			fmt.Println("Fix: gcpx schedule install")
			return 1
		}
		fmt.Println("installed")
		fmt.Println(line)
		fmt.Printf("log: %s\n", logPath)
		return 0
	case "install":
		if !schedule.Available() {
			return errf("no crontab binary on this host; run 'gcpx refresh --all' from whatever scheduler you do have")
		}
		line, err := schedule.Install(schedule.SelfPath(), *interval, logPath)
		if err != nil {
			return errf("%v", err)
		}
		fmt.Println("Installed: " + line)
		fmt.Println("")
		fmt.Println("Refreshing does not make a credential immortal. It resets the inactivity")
		fmt.Println("clock, keeps a warm token, and surfaces a dead credential within one")
		fmt.Println("interval instead of when a job trips over it.")
		return 0
	case "uninstall":
		removed, err := schedule.Uninstall()
		if err != nil {
			return errf("%v", err)
		}
		if !removed {
			fmt.Println("nothing to remove")
			return 0
		}
		fmt.Println("Removed the gcpx cron entry.")
		return 0
	default:
		return errf("unknown subcommand %q (install|uninstall|status|print)", sub)
	}
}

func cmdSelfUpdate(args []string) int {
	fs := flag.NewFlagSet("self-update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	check := fs.Bool("check", false, "report the latest version without installing")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	tag, err := updater.Latest(ctx)
	if err != nil {
		return errf("%v", err)
	}
	current := "v" + Version
	if Version == "dev" {
		current = "dev"
	}
	if *check {
		fmt.Printf("current %s\nlatest  %s\n", current, tag)
		if current == tag {
			return 0
		}
		return 2
	}
	if current == tag {
		fmt.Printf("already on %s\n", tag)
		return 0
	}
	if err := updater.Update(ctx, tag); err != nil {
		return errf("%v", err)
	}
	fmt.Printf("updated %s -> %s\n", current, tag)
	return 0
}

// Command gcpx selects a Google Cloud identity per command invocation.
package main

import (
	"os"

	"github.com/luutuankiet/gcpx/internal/cli"
)

var version = "dev"

func main() {
	cli.Version = version
	os.Exit(cli.Run(os.Args[1:]))
}

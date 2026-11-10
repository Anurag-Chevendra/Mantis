// Command mantis reads npm lockfiles and checks pinned dependencies against
// Cohen. See https://github.com/Anurag-Chevendra/mantis.
package main

import (
	"os"

	"github.com/Anurag-Chevendra/mantis/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], cli.DefaultEnv()))
}

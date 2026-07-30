// Command ehjint is the single EHJINT multicall runtime entrypoint.
package main

import (
	"os"

	"github.com/StealthEyeLLC/ehjint/internal/app"
)

func main() {
	os.Exit(app.Run(os.Args[0], os.Args[1:], os.Stdout, os.Stderr))
}

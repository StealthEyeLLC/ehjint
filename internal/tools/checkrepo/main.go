// Command checkrepo enforces standalone Mission 1 repository policy.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/StealthEyeLLC/ehjint/internal/repositorycheck"
)

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if flag.NArg() != 0 {
		fatalf("unexpected positional arguments")
	}
	absolute, err := filepath.Abs(*root)
	if err != nil {
		fatalf("resolve root: %v", err)
	}
	report, err := repositorycheck.Check(absolute)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("repository checks passed: files=%d checks=%s\n", report.FileCount, strings.Join(report.Checks, ","))
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "checkrepo: "+format+"\n", arguments...)
	os.Exit(1)
}

// Command egressgate is a deny-by-default forward proxy for headless coding
// agents, with a tamper-evident audit log.
//
// All of the behaviour lives in run, so the command is testable without
// spawning a process.
package main

import (
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"interceptor/internal/detect"
	"interceptor/internal/mcp"
	"interceptor/internal/report"
	"interceptor/internal/scan"
)

const usage = `usage: interceptor scan [--json] [--fail-on low|medium|high|critical] [--stdio "<command>"] [path]

Scans MCP tool manifests for poisoning, unicode smuggling, embedded
secrets, and credential-harvesting parameters.

  path             a manifest .json file or a directory of them
  --stdio "<cmd>"  launch an MCP stdio server and scan its live tools/list
  --json           emit the report as JSON
  --fail-on        minimum severity causing exit code 1 (default: high)
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 || args[0] != "scan" {
		fmt.Fprint(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON report")
	failOn := fs.String("fail-on", "high", "minimum severity that causes exit code 1")
	stdioCmd := fs.String("stdio", "", "command launching an MCP stdio server")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	threshold := detect.Severity(*failOn)
	if threshold.Rank() == 0 {
		fmt.Fprintf(stderr, "invalid --fail-on value %q\n", *failOn)
		return 2
	}

	var rep *scan.Report
	switch {
	case *stdioCmd != "":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		m, err := mcp.ScanStdioServer(ctx, *stdioCmd)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
		rep = scan.Manifests([]detect.Manifest{m})
	case fs.NArg() == 1:
		var err error
		rep, err = scan.Path(fs.Arg(0))
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}

	if *jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return 2
		}
	} else {
		fmt.Fprint(stdout, report.Terminal(rep))
		fmt.Fprintln(stdout, "badge:", report.BadgeURL(len(rep.Findings)))
	}

	for _, f := range rep.Findings {
		if f.Severity.Rank() >= threshold.Rank() {
			return 1
		}
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

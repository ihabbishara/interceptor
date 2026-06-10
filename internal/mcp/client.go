package mcp

import (
	"context"
	"fmt"

	"interceptor/internal/detect"
)

// ScanStdioServer launches an MCP stdio server and returns its live tool
// manifest. Implemented in the stdio-client task.
func ScanStdioServer(ctx context.Context, command string) (detect.Manifest, error) {
	return detect.Manifest{}, fmt.Errorf("stdio scanning not yet implemented")
}

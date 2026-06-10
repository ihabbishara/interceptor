package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"syscall"

	"interceptor/internal/detect"
)

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// listToolsOverStream performs the MCP handshake and tools/list over
// newline-delimited JSON-RPC (the MCP stdio transport framing).
func listToolsOverStream(in io.Reader, out io.Writer, serverLabel string) (detect.Manifest, error) {
	enc := json.NewEncoder(out)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	recv := func(wantID int) (json.RawMessage, error) {
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var resp rpcResponse
			if err := json.Unmarshal(line, &resp); err != nil {
				continue // server log noise on stdout; skip
			}
			if resp.Error != nil {
				return nil, fmt.Errorf("rpc error %d: %s", resp.Error.Code, resp.Error.Message)
			}
			if resp.ID == wantID {
				return resp.Result, nil
			}
		}
		return nil, fmt.Errorf("server closed stream before responding to request %d", wantID)
	}

	if err := enc.Encode(rpcRequest{JSONRPC: "2.0", ID: 1, Method: "initialize", Params: map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "interceptor-scanner", "version": "0.1.0"},
	}}); err != nil {
		return detect.Manifest{}, err
	}
	if _, err := recv(1); err != nil {
		return detect.Manifest{}, fmt.Errorf("initialize failed: %w", err)
	}
	if err := enc.Encode(rpcRequest{JSONRPC: "2.0", Method: "notifications/initialized"}); err != nil {
		return detect.Manifest{}, err
	}
	if err := enc.Encode(rpcRequest{JSONRPC: "2.0", ID: 2, Method: "tools/list", Params: map[string]any{}}); err != nil {
		return detect.Manifest{}, err
	}
	result, err := recv(2)
	if err != nil {
		return detect.Manifest{}, fmt.Errorf("tools/list failed: %w", err)
	}

	var lr struct {
		Tools []detect.ToolDef `json:"tools"`
	}
	if err := json.Unmarshal(result, &lr); err != nil {
		return detect.Manifest{}, fmt.Errorf("bad tools/list result: %w", err)
	}
	return detect.Manifest{Server: serverLabel, Tools: lr.Tools}, nil
}

// ScanStdioServer launches the given shell command as an MCP stdio server
// and returns its live tool manifest.
func ScanStdioServer(ctx context.Context, command string) (detect.Manifest, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	// Put the child in its own process group so we can kill the entire group
	// (including grandchildren such as the real server spawned by npx/sh) when
	// the context deadline fires.  Without Setpgid, only the direct "sh" child
	// is killed; grandchildren keep the stdout pipe open and sc.Scan() blocks
	// indefinitely.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return detect.Manifest{}, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return detect.Manifest{}, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return detect.Manifest{}, fmt.Errorf("launching %q: %w", command, err)
	}

	// Watchdog: when the context is cancelled (deadline or explicit cancel),
	// kill the entire process group so all grandchildren release the pipe.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		case <-done:
		}
	}()

	defer func() {
		close(done)
		stdin.Close()
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		cmd.Wait()
	}()
	return listToolsOverStream(stdout, stdin, command)
}

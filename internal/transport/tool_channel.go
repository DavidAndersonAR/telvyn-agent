package transport

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ispwatch/collector/internal/tools"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// ToolChannel opens the reverse RPC where the central server pushes
// ToolCommands and the Collector returns ToolResults. Each command runs in
// its own goroutine so a slow tool doesn't block the channel.
//
// Returns the error that broke the stream so RunForever can decide whether
// to reconnect. nil on clean ctx cancellation.
func (c *Conn) ToolChannel(ctx context.Context, log *slog.Logger, registry *tools.Registry) error {
	stream, err := c.client.ToolChannel(ctx)
	if err != nil {
		return fmt.Errorf("open ToolChannel: %w", err)
	}

	for {
		cmd, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("ToolChannel recv: %w", err)
		}

		go func(cmd *collectorv1.ToolCommand) {
			result := executeOne(ctx, log, registry, cmd)
			if err := stream.Send(result); err != nil {
				log.Warn("ToolChannel send result failed", "command_id", cmd.GetCommandId(), "err", err)
			}
		}(cmd)
	}
}

func executeOne(parentCtx context.Context, log *slog.Logger, registry *tools.Registry,
	cmd *collectorv1.ToolCommand) *collectorv1.ToolResult {

	res := &collectorv1.ToolResult{CommandId: cmd.GetCommandId()}
	start := time.Now()
	defer func() { res.DurationMs = time.Since(start).Milliseconds() }()

	exec, ok := registry.Get(cmd.GetTool())
	if !ok {
		log.Warn("unknown tool requested", "command_id", cmd.GetCommandId(), "tool", cmd.GetTool())
		res.Ok = false
		res.Error = tools.ErrUnknownTool.Error() + ": " + cmd.GetTool()
		return res
	}

	timeout := time.Duration(cmd.GetTimeoutSeconds()) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cmdCtx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	args := tools.ToMap(cmd.GetArgs())
	out, err := exec.Execute(cmdCtx, args)
	if err != nil {
		// Don't leak credential bytes via err string. The executor builds
		// errors from arg names + system errors, but be defensive.
		log.Warn("tool execution failed", "command_id", cmd.GetCommandId(),
			"tool", cmd.GetTool(), "err", err)
		res.Ok = false
		res.Error = err.Error()
		return res
	}

	resultStruct, sErr := tools.ToStruct(out)
	if sErr != nil {
		log.Warn("result serialization failed", "command_id", cmd.GetCommandId(), "err", sErr)
		res.Ok = false
		res.Error = "result serialization failed: " + sErr.Error()
		return res
	}
	res.Ok = true
	res.Result = resultStruct
	return res
}

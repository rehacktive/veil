// Package diagnostics provides explicitly enabled, per-instance debug output.
package diagnostics

import (
	"context"
	"io"
	"log/slog"
)

type contextKey struct{}

// New never installs a global logger. Disabled logging has no output destination.
func New(enabled bool, out io.Writer) *slog.Logger {
	if !enabled {
		return nil
	}
	return slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	if logger == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, logger)
}

// Log uses request attributes when supplied by the SOCKS frontend. A nil fallback
// disables logging, even if another caller has attached a logger to the context.
func Log(ctx context.Context, fallback *slog.Logger, event string, attrs ...any) {
	if fallback == nil {
		return
	}
	logger, ok := ctx.Value(contextKey{}).(*slog.Logger)
	if !ok {
		logger = fallback
	}
	logger.DebugContext(ctx, event, attrs...)
}

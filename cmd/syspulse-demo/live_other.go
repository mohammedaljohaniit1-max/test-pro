//go:build !linux

package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/mohammedaljohaniit1-max/test-pro/internal/hub"
	"github.com/mohammedaljohaniit1-max/test-pro/internal/server"
)

func liveStack(ctx context.Context, log *slog.Logger, addr string, selfTest, noResolve bool) (*hub.Hub, *server.Server, error) {
	return nil, nil, errors.New("the preview binary collects live data on Linux only; on Windows run syspulse.exe")
}

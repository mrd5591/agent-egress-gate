package main

import (
	"context"
	"os/signal"
	"syscall"
)

// signalContext is cancelled on the signals a container runtime uses to ask
// for a graceful stop.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

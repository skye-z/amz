package amz

import (
	"context"

	"github.com/skye-z/amz/observe"
	"github.com/skye-z/amz/types"
)

type Runtime = types.Tunnel

type ListenerRuntime interface {
	Runtime
	ListenAddress() string
}

type HTTPProxy interface {
	ListenerRuntime
}

type SOCKS5Proxy interface {
	ListenerRuntime
}

type Tunnel interface {
	Runtime
}

type Event = observe.Event
type EventHandler = observe.EventHandler
type Stats = observe.Stats

func Start(ctx context.Context, runtime Runtime) error {
	return runtime.Start(ctx)
}

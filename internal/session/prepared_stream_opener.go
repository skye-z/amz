package session

import (
	"context"
	"fmt"
	"net"
)

type streamPreparer interface {
	PrepareStream(context.Context) error
}

type connectStreamOpener interface {
	OpenStream(context.Context, string, string) (net.Conn, error)
}

type preparedConnectStreamOpener struct {
	preparer streamPreparer
	manager  connectStreamOpener
}

func NewPreparedConnectStreamOpener(preparer streamPreparer, manager connectStreamOpener) *preparedConnectStreamOpener {
	if manager == nil {
		return nil
	}
	return &preparedConnectStreamOpener{
		preparer: preparer,
		manager:  manager,
	}
}

func NewPreparedProxyStreamOpener(preparer streamPreparer, manager *ConnectStreamManager) *preparedConnectStreamOpener {
	if manager == nil {
		return nil
	}
	manager.EnableProxyMode()
	return NewPreparedConnectStreamOpener(preparer, manager)
}

func (o *preparedConnectStreamOpener) OpenStream(ctx context.Context, host, port string) (net.Conn, error) {
	if o == nil || o.manager == nil {
		return nil, fmt.Errorf("connect stream manager is required")
	}
	if o.preparer != nil {
		if err := o.preparer.PrepareStream(ctx); err != nil {
			return nil, err
		}
	}
	return o.manager.OpenStream(ctx, host, port)
}

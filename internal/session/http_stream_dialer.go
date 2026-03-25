package session

import (
	"context"
	"net"
)

// HTTPStreamDialer ?????????? bootstrap dialer ???????
type HTTPStreamDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

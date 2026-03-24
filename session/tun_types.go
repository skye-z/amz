package session

import "context"

// TUNDevice ????????? TUN ???????
type TUNDevice interface {
	Name() string
	MTU() int
	ReadPacket(context.Context, []byte) (int, error)
	WritePacket(context.Context, []byte) (int, error)
	Close() error
}

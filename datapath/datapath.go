package datapath

import "github.com/skye-z/amz/kernel"

type PacketRelayEndpoint = kernel.PacketRelayEndpoint
type PacketIO = kernel.PacketIO

func NewPacketIO(mtu int) *PacketIO {
	return kernel.NewPacketIO(mtu)
}

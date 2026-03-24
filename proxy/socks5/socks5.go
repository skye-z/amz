package socks5

import (
	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
)

type Snapshot = kernel.SOCKSSnapshot
type UDPAssociateRequest = kernel.UDPAssociateRequest
type UDPAssociateResponse = kernel.UDPAssociateResponse
type UDPAssociateRelay = kernel.UDPAssociateRelay
type Manager = kernel.SOCKSManager

func NewManager(cfg *config.KernelConfig) (*Manager, error) {
	return kernel.NewSOCKSManager(cfg)
}

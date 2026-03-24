package tun

import (
	"github.com/skye-z/amz/config"
	"github.com/skye-z/amz/kernel"
)

type Runtime = kernel.Tunnel
type Device = kernel.TUNDevice
type DeviceConfig = kernel.TUNDeviceConfig
type Address = kernel.TUNAddress
type Configuration = kernel.TUNConfiguration
type ConfigSnapshot = kernel.TUNConfigSnapshot
type ConfigManager = kernel.TUNConfigManager
type RouteMode = kernel.RouteMode
type RoutePlan = kernel.RoutePlan
type RouteSnapshot = kernel.RouteSnapshot
type RouteManager = kernel.RouteManager
type FakeDevice = kernel.FakeTUNDevice

func NewRuntime(cfg *config.KernelConfig) (*Runtime, error) {
	return kernel.NewTunnel(cfg)
}

func NewConfigManager(cfg Configuration) (*ConfigManager, error) {
	return kernel.NewTUNConfigManager(cfg)
}

func NewRouteManager(plan RoutePlan) (*RouteManager, error) {
	return kernel.NewRouteManager(plan)
}

func NewFakeDevice(cfg DeviceConfig) (*FakeDevice, error) {
	return kernel.NewFakeTUNDevice(cfg)
}

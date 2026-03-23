package tun

import (
	"context"
	"fmt"
	"runtime"

	"github.com/skye-z/amz/types"
)

// 描述带平台元信息的占位 provider 行为。
type PlatformProvider interface {
	Provider
	Platform() string
	IsFake() bool
}

// 返回当前运行平台对应的占位 provider。
func NewProvider() (PlatformProvider, error) {
	return NewProviderForOS(runtime.GOOS)
}

// 按给定平台名称返回对应的占位 provider。
func NewProviderForOS(goos string) (PlatformProvider, error) {
	switch goos {
	case platformLinux:
		return newLinuxProvider(), nil
	case platformDarwin:
		return newDarwinProvider(), nil
	case platformWindows:
		return newWindowsProvider(), nil
	default:
		return nil, fmt.Errorf("%w: unsupported tun platform %q", types.ErrInvalidConfig, goos)
	}
}

// 返回当前骨架阶段使用的平台名称。
func PlatformName(goos string) string {
	return goos
}

// 提供平台占位实现的最小公共行为，底层仍复用假设备。
type placeholderProvider struct {
	platform string
	delegate *FakeProvider
}

// 返回占位 provider 对应的平台名称。
func (p *placeholderProvider) Platform() string {
	return p.platform
}

// 标记当前实现仍是不会触发真实系统调用的假实现。
func (p *placeholderProvider) IsFake() bool {
	return true
}

// 打开一个平台占位设备，实际返回内存假设备。
func (p *placeholderProvider) Open(ctx context.Context, cfg DeviceConfig) (*FakeDevice, error) {
	return p.delegate.Open(ctx, cfg)
}

// 关闭平台占位 provider，并级联关闭其创建的假设备。
func (p *placeholderProvider) Close() error {
	return p.delegate.Close()
}

// 创建一个绑定到指定平台名称的占位 provider。
func newPlaceholderProvider(platform string) PlatformProvider {
	return &placeholderProvider{
		platform: PlatformName(platform),
		delegate: NewFakeProvider(),
	}
}

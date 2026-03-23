package tun

import (
	"context"
	"fmt"
	"runtime"

	"github.com/skye-z/amz/types"
)

// 描述 TUN 骨架阶段对未实现平台能力的结构化占位错误。
type PlaceholderError struct {
	Platform  string
	Component string
}

// 返回便于上层展示的未实现错误描述。
func (e *PlaceholderError) Error() string {
	return fmt.Sprintf("%s %s: %v", e.Platform, e.Component, types.ErrNotImplemented)
}

// 支持使用 errors.Is 判断未实现占位信号。
func (e *PlaceholderError) Unwrap() error {
	return types.ErrNotImplemented
}

// 描述带平台元信息的占位 provider 行为。
type PlatformProvider interface {
	Provider
	Platform() string
	IsFake() bool
	PlaceholderError() error
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

// 返回当前 provider 仍为占位实现的结构化错误。
func (p *placeholderProvider) PlaceholderError() error {
	return &PlaceholderError{
		Platform:  p.platform,
		Component: "provider",
	}
}

// 打开一个平台占位设备，实际返回内存假设备。
func (p *placeholderProvider) Open(ctx context.Context, cfg DeviceConfig) (Device, error) {
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

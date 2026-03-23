package tun

const platformDarwin = "darwin"

// 返回 macOS 平台的占位 provider，后续可替换为真实实现。
func newDarwinProvider() PlatformProvider {
	return newPlaceholderProvider(platformDarwin)
}

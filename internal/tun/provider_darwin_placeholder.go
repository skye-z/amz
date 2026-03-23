package tun

const platformDarwin = "darwin"

// 返回 macOS 平台的 sing-tun provider。
func newDarwinProvider() PlatformProvider {
	return newSingProvider(platformDarwin)
}

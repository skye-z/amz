package tun

const platformWindows = "windows"

// 返回 Windows 平台的 sing-tun provider。
func newWindowsProvider() PlatformProvider {
	return newSingProvider(platformWindows)
}

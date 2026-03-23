package tun

const platformWindows = "windows"

// 返回 Windows 平台的占位 provider，后续可替换为真实实现。
func newWindowsProvider() PlatformProvider {
	return newPlaceholderProvider(platformWindows)
}

package tun

const platformLinux = "linux"

// 返回 Linux 平台的占位 provider，后续可替换为真实实现。
func newLinuxProvider() PlatformProvider {
	return newPlaceholderProvider(platformLinux)
}

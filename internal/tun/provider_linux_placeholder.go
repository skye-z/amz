package tun

const platformLinux = "linux"

// 返回 Linux 平台的 sing-tun provider。
func newLinuxProvider() PlatformProvider {
	return newSingProvider(platformLinux)
}

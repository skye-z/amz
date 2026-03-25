package masque

import "strings"

const debugTarget = "ipwho.is:443"

func IsDebugTarget(target string) bool {
	return strings.TrimSpace(target) == debugTarget
}

func ShouldDebugTarget(enabled bool, target string) bool {
	return enabled && IsDebugTarget(target)
}

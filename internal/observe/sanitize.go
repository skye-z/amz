package observe

import "regexp"

var sensitiveValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(endpoint\s*=\s*token\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(token\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(api[_-]?key\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(refresh[_-]?token\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(license(?:[_-]?key)?\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(warp[_-]?plus[_-]?license\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(private[_-]?key\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(device[_-]?credentials\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(password\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(secret\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)("token"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("api[_-]?key"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("refresh[_-]?token"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("license(?:[_-]?key)?"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("warp[_-]?plus[_-]?license"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("private[_-]?key"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("device[_-]?credentials"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("password"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("secret"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("apiKey"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("refreshToken"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("licenseKey"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("warpPlusLicense"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("privateKey"\s*:\s*")([^"]+)(")`),
	regexp.MustCompile(`(?i)("deviceCredentials"\s*:\s*")([^"]+)(")`),
}

func SanitizeError(err error) string {
	if err == nil {
		return ""
	}
	return SanitizeText(err.Error())
}

func SanitizeText(text string) string {
	masked := text
	for _, pattern := range sensitiveValuePatterns {
		masked = pattern.ReplaceAllString(masked, `${1}<redacted>${3}`)
	}
	return masked
}

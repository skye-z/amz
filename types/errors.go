package types

import "regexp"

var sensitiveValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(endpoint\s*=\s*token\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(token\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(private[_-]?key\s*=\s*)([^\s,;]+)`),
	regexp.MustCompile(`(?i)(device[_-]?credentials\s*=\s*)([^\s,;]+)`),
}

// 返回去除敏感字段值后的错误字符串。
func SanitizeError(err error) string {
	if err == nil {
		return ""
	}
	return SanitizeText(err.Error())
}

// 返回去除常见敏感字段值后的文本。
func SanitizeText(text string) string {
	masked := text
	for _, pattern := range sensitiveValuePatterns {
		masked = pattern.ReplaceAllString(masked, `${1}<redacted>`)
	}
	return masked
}

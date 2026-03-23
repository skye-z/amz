package config_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

var goVersionLinePattern = regexp.MustCompile(`(?m)^go\s+1\.(\d+)(?:\.\d+)?$`)

// 验证工作区与双模块的 Go 版本声明已统一到 1.24+。
func TestWorkspaceGoVersionsAreUnifiedTo124Plus(t *testing.T) {
	t.Parallel()

	files := []string{
		filepath.Join("..", "..", "go.work"),
		filepath.Join("..", "go.mod"),
		filepath.Join("..", "..", "igara", "go.mod"),
	}

	for _, path := range files {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			matches := goVersionLinePattern.FindSubmatch(content)
			if len(matches) != 2 {
				t.Fatalf("missing go version declaration in %s", path)
			}

			minor, err := strconv.Atoi(string(matches[1]))
			if err != nil {
				t.Fatalf("parse go minor version from %s: %v", path, err)
			}

			if minor < 24 {
				t.Fatalf("expected Go version in %s to be 1.24+, got 1.%d", path, minor)
			}
		})
	}
}

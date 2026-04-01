package config_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

var goVersionLinePattern = regexp.MustCompile(`(?m)^go\s+1\.(\d+)(?:\.\d+)?$`)

func TestWorkspaceGoVersionsAreUnifiedTo124Plus(t *testing.T) {
	t.Parallel()

	files := existingGoVersionFiles(t, []string{
		filepath.Join("..", "..", "..", "go.work"),
		filepath.Join("..", "..", "go.mod"),
		filepath.Join("..", "..", "..", "igara", "go.mod"),
	})
	for _, path := range files {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			assertGoVersionAtLeast124(t, path)
		})
	}
}

func existingGoVersionFiles(t *testing.T, candidates []string) []string {
	t.Helper()

	files := make([]string, 0, len(candidates))
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			files = append(files, path)
		}
	}
	if len(files) == 0 {
		t.Fatal("expected at least one go version file to validate")
	}
	return files
}

func assertGoVersionAtLeast124(t *testing.T, path string) {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	minor := parseGoMinorVersion(t, path, content)
	if minor < 24 {
		t.Fatalf("expected Go version in %s to be 1.24+, got 1.%d", path, minor)
	}
}

func parseGoMinorVersion(t *testing.T, path string, content []byte) int {
	t.Helper()

	matches := goVersionLinePattern.FindSubmatch(content)
	if len(matches) != 2 {
		t.Fatalf("missing go version declaration in %s", path)
	}
	minor, err := strconv.Atoi(string(matches[1]))
	if err != nil {
		t.Fatalf("parse go minor version from %s: %v", path, err)
	}
	return minor
}

package amz

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSDKLayoutRemovesMigratedTopLevelDirs(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("expected caller info")
	}
	root := filepath.Dir(file)
	for _, name := range []string{"cloudflare", "observe", "session"} {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			t.Fatalf("expected migrated top-level dir %q to be removed", name)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "proxy")); err == nil {
		t.Fatal("expected migrated top-level dir \"proxy\" to be removed")
	}
	if _, err := os.Stat(filepath.Join(root, "tun")); err == nil {
		t.Fatal("expected migrated top-level dir \"tun\" to be removed")
	}
	if _, err := os.Stat(filepath.Join(root, "datapath")); err == nil {
		t.Fatal("expected migrated top-level dir \"datapath\" to be removed")
	}
	if _, err := os.Stat(filepath.Join(root, "types")); err == nil {
		t.Fatal("expected migrated top-level dir \"types\" to be removed")
	}
	if _, err := os.Stat(filepath.Join(root, "config")); err == nil {
		t.Fatal("expected migrated top-level dir \"config\" to be removed")
	}
	if _, err := os.Stat(filepath.Join(root, "internal", "contracts")); err == nil {
		t.Fatal("expected internal/contracts to be folded into target internal packages")
	}
	for _, name := range []string{"http.go", "socks5.go", "tun.go", "runtime.go"} {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			t.Fatalf("expected legacy root wrapper file %q to be removed", name)
		}
	}
}

func TestSDKLayoutStopsUsingTopLevelSessionInProductionPaths(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("expected caller info")
	}
	root := filepath.Dir(file)
	for _, rel := range []string{
		"sdk_runtime.go",
		filepath.Join("internal", "runtime", "factories.go"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if strings.Contains(string(data), `"github.com/skye-z/amz/session"`) {
			t.Fatalf("expected %s to stop importing top-level session package", rel)
		}
	}
}

func TestInternalManagersStopUsingTypesSanitizers(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("expected caller info")
	}
	root := filepath.Dir(file)
	for _, rel := range []string{
		filepath.Join("internal", "runtime", "http_manager.go"),
		filepath.Join("internal", "runtime", "socks5_manager.go"),
		filepath.Join("internal", "runtime", "tun_manager.go"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		if strings.Contains(text, "types.SanitizeText") || strings.Contains(text, "types.SanitizeError") {
			t.Fatalf("expected %s to stop using top-level types sanitizers", rel)
		}
	}
}

func TestInternalSessionCloudflareStopsUsingTopLevelTypes(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("expected caller info")
	}
	root := filepath.Dir(file)
	data, err := os.ReadFile(filepath.Join(root, "internal", "session", "cloudflare.go"))
	if err != nil {
		t.Fatalf("read internal/session/cloudflare.go: %v", err)
	}
	if strings.Contains(string(data), `"github.com/skye-z/amz/types"`) {
		t.Fatal("expected internal/session/cloudflare.go to stop using top-level types")
	}
}

func TestConfigStopsUsingTopLevelTypes(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("expected caller info")
	}
	root := filepath.Dir(file)
	data, err := os.ReadFile(filepath.Join(root, "internal", "config", "config.go"))
	if err != nil {
		t.Fatalf("read internal/config/config.go: %v", err)
	}
	if strings.Contains(string(data), `"github.com/skye-z/amz/types"`) {
		t.Fatal("expected internal/config/config.go to stop using top-level types")
	}
}

func TestProductionCodeStopsUsingTopLevelConfigPackage(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("expected caller info")
	}
	root := filepath.Dir(file)
	for _, rel := range []string{
		"sdk_runtime.go",
		filepath.Join("internal", "runtime", "factories.go"),
		filepath.Join("internal", "runtime", "http_manager.go"),
		filepath.Join("internal", "runtime", "socks5_manager.go"),
		filepath.Join("internal", "runtime", "tun_manager.go"),
		filepath.Join("internal", "session", "cloudflare.go"),
		filepath.Join("internal", "session", "connect_stream.go"),
		filepath.Join("internal", "session", "connectip.go"),
		filepath.Join("internal", "session", "core_tunnel_dialer.go"),
		filepath.Join("internal", "session", "datapath.go"),
		filepath.Join("internal", "session", "quic.go"),
		filepath.Join("internal", "transport", "datapath.go"),
	} {
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(data)
		if strings.Contains(text, `"github.com/skye-z/amz/config"`) {
			t.Fatalf("expected %s to stop importing top-level config package", rel)
		}
		if !strings.Contains(text, `"github.com/skye-z/amz/internal/config"`) {
			t.Fatalf("expected %s to import internal/config", rel)
		}
	}
}

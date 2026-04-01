package masque

import "testing"

const masqueDebugAuthority = "ipwho.is:443"

func TestIsDebugTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{name: "matches ipwhois authority", target: masqueDebugAuthority, want: true},
		{name: "trims surrounding spaces", target: "  " + masqueDebugAuthority + "  ", want: true},
		{name: "rejects other host", target: "betax.dev:443", want: false},
		{name: "rejects missing port", target: "ipwho.is", want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsDebugTarget(tt.target); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestShouldDebugTarget(t *testing.T) {
	t.Parallel()

	if !ShouldDebugTarget(true, masqueDebugAuthority) {
		t.Fatal("expected debug target to be enabled when switch is on")
	}
	if ShouldDebugTarget(false, masqueDebugAuthority) {
		t.Fatal("expected disabled switch to suppress debug target")
	}
	if ShouldDebugTarget(true, "betax.dev:443") {
		t.Fatal("expected non-debug target to stay disabled")
	}
}

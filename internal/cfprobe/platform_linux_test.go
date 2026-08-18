//go:build linux

package cfprobe

import "testing"

func TestRequireInstallPermissionAllowsExplicitUserBackground(t *testing.T) {
	paths := Paths{
		UserMode:       true,
		UserBackground: true,
		RunUser:        "hpc-user",
	}
	if err := requireInstallPermission(paths); err != nil {
		t.Fatalf("requireInstallPermission() error = %v, want nil", err)
	}
}

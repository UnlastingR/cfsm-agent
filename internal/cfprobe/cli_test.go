package cfprobe

import "testing"

func TestParseUninstallArgsAllowsNoArgs(t *testing.T) {
	if err := parseUninstallArgs(nil); err != nil {
		t.Fatalf("parseUninstallArgs(nil) error = %v", err)
	}
}

func TestParseInstallOptionsRejectsCustomPathAndService(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "install dir underscore", args: []string{"-install_dir=/tmp/cf-probe"}},
		{name: "install dir hyphen", args: []string{"-install-dir=/tmp/cf-probe"}},
		{name: "service name underscore", args: []string{"-service_name=probe-a"}},
		{name: "service name hyphen", args: []string{"-service-name=probe-a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseInstallOptions(tt.args); err == nil {
				t.Fatalf("parseInstallOptions(%v) expected error", tt.args)
			}
		})
	}
}

func TestParseUninstallArgsRejectsExtraArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "service name underscore", args: []string{"-service_name=probe-a"}},
		{name: "service name hyphen", args: []string{"-service-name=probe-a"}},
		{name: "positional arg", args: []string{"probe-a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := parseUninstallArgs(tt.args); err == nil {
				t.Fatalf("parseUninstallArgs(%v) expected error", tt.args)
			}
		})
	}
}

func TestParseInstallOptionsAutoUpdateDefaultOff(t *testing.T) {
	got, err := parseInstallOptions(nil)
	if err != nil {
		t.Fatalf("parseInstallOptions(nil) error = %v", err)
	}
	if got.AutoUpdate {
		t.Fatal("AutoUpdate = true, want false")
	}
}

func TestParseInstallOptionsAutoUpdateEnabled(t *testing.T) {
	got, err := parseInstallOptions([]string{"-auto_update=1"})
	if err != nil {
		t.Fatalf("parseInstallOptions(-auto_update=1) error = %v", err)
	}
	if !got.AutoUpdate {
		t.Fatal("AutoUpdate = false, want true")
	}
}

func TestParseInstallOptionsInstallProxy(t *testing.T) {
	got, err := parseInstallOptions([]string{"--install-ghproxy=https://gh-proxy.example.com"})
	if err != nil {
		t.Fatalf("parseInstallOptions(--install-ghproxy) error = %v", err)
	}
	if got.UpdateProxy != "https://gh-proxy.example.com" {
		t.Fatalf("UpdateProxy = %q", got.UpdateProxy)
	}
}

func TestParseInstallOptionsUserBackground(t *testing.T) {
	got, err := parseInstallOptions([]string{"--user-background=1"})
	if err != nil {
		t.Fatalf("parseInstallOptions(--user-background=1) error = %v", err)
	}
	if !got.UserBackground {
		t.Fatal("UserBackground = false, want true")
	}
	if !got.Explicit["user_background"] {
		t.Fatal("Explicit[user_background] = false, want true")
	}
	if _, err := parseInstallOptions([]string{"-user_background=bad"}); err == nil {
		t.Fatal("parseInstallOptions(-user_background=bad) expected error")
	}
}

func TestParseInstallOptionsConnectionMode(t *testing.T) {
	got, err := parseInstallOptions([]string{"-connection_mode=http"})
	if err != nil {
		t.Fatalf("parseInstallOptions(-connection_mode=http) error = %v", err)
	}
	if got.ConnectionMode != connectionModeHTTP {
		t.Fatalf("ConnectionMode = %q, want %q", got.ConnectionMode, connectionModeHTTP)
	}

	got, err = parseInstallOptions([]string{"--connection-mode=websocket"})
	if err != nil {
		t.Fatalf("parseInstallOptions(--connection-mode=websocket) error = %v", err)
	}
	if got.ConnectionMode != connectionModeAuto {
		t.Fatalf("ConnectionMode = %q, want %q", got.ConnectionMode, connectionModeAuto)
	}

	if _, err := parseInstallOptions([]string{"-connection_mode=bad"}); err == nil {
		t.Fatal("parseInstallOptions(-connection_mode=bad) expected error")
	}
}

func TestParseInstallOptionsTracksExplicitFlags(t *testing.T) {
	got, err := parseInstallOptions([]string{"-auto_update=1", "--auto-update=1", "-collect=5", "-connection_mode=http", "--install-ghproxy=https://gh-proxy.example.com", "--user-background=1"})
	if err != nil {
		t.Fatalf("parseInstallOptions() error = %v", err)
	}
	for _, name := range []string{"auto_update", "collect_interval", "connection_mode", "install_ghproxy", "user_background"} {
		if !got.Explicit[name] {
			t.Fatalf("Explicit[%q] = false, want true (all: %v)", name, got.Explicit)
		}
	}
	if got.Explicit["reset_day"] || got.Explicit["interface"] {
		t.Fatalf("unexpected explicit flags: %v", got.Explicit)
	}
}

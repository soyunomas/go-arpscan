package config

import (
	"testing"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func intPtr(v int) *int { return &v }

func testCommandWithVLAN(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Int("vlan", -1, "")
	cmd.Flags().Bool("exclude-broadcast", false, "")
	return cmd
}

func TestAdvancedVLANPreservesZero(t *testing.T) {
	var appCfg AppConfig
	if err := yaml.Unmarshal([]byte("advanced:\n  vlan: 0\n"), &appCfg); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if appCfg.Advanced.Vlan == nil {
		t.Fatal("advanced.vlan should be non-nil when explicitly set to 0")
	}

	cfg := &ResolvedConfig{VlanID: -1}
	applyAppConfig(testCommandWithVLAN(t), cfg, &appCfg)
	if cfg.VlanID != 0 {
		t.Fatalf("VlanID = %d, want 0", cfg.VlanID)
	}
}

func TestAdvancedVLANOmittedLeavesDefault(t *testing.T) {
	var appCfg AppConfig
	if err := yaml.Unmarshal([]byte("advanced: {}\n"), &appCfg); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if appCfg.Advanced.Vlan != nil {
		t.Fatalf("advanced.vlan = %v, want nil when omitted", *appCfg.Advanced.Vlan)
	}

	cfg := &ResolvedConfig{VlanID: -1}
	applyAppConfig(testCommandWithVLAN(t), cfg, &appCfg)
	if cfg.VlanID != -1 {
		t.Fatalf("VlanID = %d, want -1", cfg.VlanID)
	}
}

func TestProfileVLANPreservesZero(t *testing.T) {
	cfg := &ResolvedConfig{VlanID: -1}
	applyProfile(testCommandWithVLAN(t), cfg, &ProfileConfig{Vlan: intPtr(0)})
	if cfg.VlanID != 0 {
		t.Fatalf("VlanID = %d, want 0", cfg.VlanID)
	}
}

func TestProfileVLANDoesNotOverrideExplicitFlag(t *testing.T) {
	cmd := testCommandWithVLAN(t)
	if err := cmd.Flags().Set("vlan", "7"); err != nil {
		t.Fatalf("Set vlan: %v", err)
	}

	cfg := &ResolvedConfig{VlanID: 7}
	applyProfile(cmd, cfg, &ProfileConfig{Vlan: intPtr(0)})
	if cfg.VlanID != 7 {
		t.Fatalf("VlanID = %d, want explicit flag value 7", cfg.VlanID)
	}
}

func TestScanExcludeBroadcastFromYAML(t *testing.T) {
	var appCfg AppConfig
	if err := yaml.Unmarshal([]byte("scan:\n  exclude-broadcast: true\n"), &appCfg); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	cfg := &ResolvedConfig{}
	applyAppConfig(testCommandWithVLAN(t), cfg, &appCfg)
	if !cfg.ExcludeBroadcast {
		t.Fatal("ExcludeBroadcast = false, want true")
	}
}

func TestScanExcludeBroadcastDoesNotOverrideExplicitFlag(t *testing.T) {
	cmd := testCommandWithVLAN(t)
	if err := cmd.Flags().Set("exclude-broadcast", "false"); err != nil {
		t.Fatalf("Set exclude-broadcast: %v", err)
	}

	cfg := &ResolvedConfig{ExcludeBroadcast: false}
	applyAppConfig(cmd, cfg, &AppConfig{Scan: ScanConfig{ExcludeBroadcast: true}})
	if cfg.ExcludeBroadcast {
		t.Fatal("ExcludeBroadcast should keep explicit flag value false")
	}
}

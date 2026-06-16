package cli

import (
	"strings"
	"testing"

	"go-arpscan/internal/config"
)

func TestValidateFlagsVLANRange(t *testing.T) {
	cases := []struct {
		name    string
		vlanID  int
		wantErr bool
	}{
		{name: "disabled", vlanID: -1},
		{name: "priority tagged vlan zero", vlanID: 0},
		{name: "lowest standard vlan", vlanID: 1},
		{name: "highest vlan", vlanID: 4095},
		{name: "below sentinel", vlanID: -2, wantErr: true},
		{name: "above range", vlanID: 4096, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateFlags(&config.ResolvedConfig{VlanID: tc.vlanID}, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateFlags(VlanID=%d): expected error", tc.vlanID)
				}
				if !strings.Contains(err.Error(), "VLAN ID") {
					t.Fatalf("ValidateFlags(VlanID=%d): unexpected error %q", tc.vlanID, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateFlags(VlanID=%d): unexpected error: %v", tc.vlanID, err)
			}
		})
	}
}

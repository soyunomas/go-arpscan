//go:build linux

package scanner

import "testing"

func TestFastEligibleVLAN(t *testing.T) {
	if !FastEligible(&Config{VlanID: -1}) {
		t.Fatal("VlanID -1 should keep the FAST engine eligible")
	}
	if FastEligible(&Config{VlanID: 0}) {
		t.Fatal("VlanID 0 should fall back to the standard engine")
	}
	if FastEligible(&Config{VlanID: 4095}) {
		t.Fatal("VlanID 4095 should fall back to the standard engine")
	}
}

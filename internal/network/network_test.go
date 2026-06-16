package network

import (
	"net"
	"testing"
)

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return ipNet
}

func hasIP(ips []net.IP, want string) bool {
	for _, ip := range ips {
		if ip.String() == want {
			return true
		}
	}
	return false
}

func TestGetIPsIncludesNetworkAndBroadcastByDefault(t *testing.T) {
	ips, err := GetIPs(mustCIDR(t, "192.168.1.0/30"), false)
	if err != nil {
		t.Fatalf("GetIPs: %v", err)
	}
	if len(ips) != 4 {
		t.Fatalf("len(GetIPs /30) = %d, want 4", len(ips))
	}
	if !hasIP(ips, "192.168.1.0") || !hasIP(ips, "192.168.1.3") {
		t.Fatalf("GetIPs should include network and broadcast, got %v", ips)
	}
}

func TestGetIPsExcludeBroadcastRestoresHostOnlyRange(t *testing.T) {
	ips, err := GetIPs(mustCIDR(t, "192.168.1.0/30"), true)
	if err != nil {
		t.Fatalf("GetIPs: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("len(GetIPs /30 exclude) = %d, want 2", len(ips))
	}
	if hasIP(ips, "192.168.1.0") || hasIP(ips, "192.168.1.3") {
		t.Fatalf("GetIPs exclude should omit network and broadcast, got %v", ips)
	}
}

func TestGetIPsSlash24Counts(t *testing.T) {
	ips, err := GetIPs(mustCIDR(t, "10.0.0.0/24"), false)
	if err != nil {
		t.Fatalf("GetIPs include: %v", err)
	}
	if len(ips) != 256 {
		t.Fatalf("len(GetIPs /24) = %d, want 256", len(ips))
	}

	ips, err = GetIPs(mustCIDR(t, "10.0.0.0/24"), true)
	if err != nil {
		t.Fatalf("GetIPs exclude: %v", err)
	}
	if len(ips) != 254 {
		t.Fatalf("len(GetIPs /24 exclude) = %d, want 254", len(ips))
	}
}

func TestResolveTargetsNetworkMaskExcludeBroadcast(t *testing.T) {
	ips, err := ResolveTargets([]string{"192.168.1.0:255.255.255.252"}, true, false)
	if err != nil {
		t.Fatalf("ResolveTargets include: %v", err)
	}
	if len(ips) != 4 {
		t.Fatalf("len(ResolveTargets network:mask) = %d, want 4", len(ips))
	}

	ips, err = ResolveTargets([]string{"192.168.1.0:255.255.255.252"}, true, true)
	if err != nil {
		t.Fatalf("ResolveTargets exclude: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("len(ResolveTargets network:mask exclude) = %d, want 2", len(ips))
	}
}

func TestResolveTargetsDoesNotTrimExplicitRanges(t *testing.T) {
	ips, err := ResolveTargets([]string{"192.168.1.0-192.168.1.3"}, true, true)
	if err != nil {
		t.Fatalf("ResolveTargets range: %v", err)
	}
	if len(ips) != 4 {
		t.Fatalf("len(ResolveTargets explicit range exclude) = %d, want 4", len(ips))
	}
}

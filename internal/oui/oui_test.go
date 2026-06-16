package oui

import "testing"

func TestNewEmptyVendorDBLookup(t *testing.T) {
	db := NewEmptyVendorDB()

	if got := db.Lookup("00:11:22:33:44:55"); got != "Unknown" {
		t.Fatalf("Lookup() = %q, want Unknown", got)
	}
	if got := db.Lookup("02:00:00:00:00:01"); got != "Unknown (Locally Administered)" {
		t.Fatalf("Lookup() = %q, want Unknown (Locally Administered)", got)
	}
}

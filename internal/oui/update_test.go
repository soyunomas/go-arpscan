package oui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateVendorFilesForcesDownloadAndRebuildsBin(t *testing.T) {
	const ouiBody = `AA-BB-CC   (hex)		Updated Vendor
00-11-22   (hex)		Beta Networks
`
	const iabBody = `AA-BB-CC-DD-E   (hex)		IAB Vendor
`

	dir := t.TempDir()
	srcOUI := filepath.Join(dir, "src-oui.txt")
	srcIAB := filepath.Join(dir, "src-iab.txt")
	ouiPath := filepath.Join(dir, "oui.txt")
	iabPath := filepath.Join(dir, "iab.txt")
	binPath := ouiPath + ".bin"

	if err := os.WriteFile(srcOUI, []byte(ouiBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(srcIAB, []byte(iabBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ouiPath, []byte("AA-BB-CC   (hex)\t\tOld Vendor\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := BuildBinFile(binPath, map[string]string{"AABBCC": "Old Vendor"}); err != nil {
		t.Fatal(err)
	}

	if err := UpdateVendorFiles(ouiPath, iabPath, "file://"+srcOUI, "file://"+srcIAB, 0); err != nil {
		t.Fatalf("UpdateVendorFiles: %v", err)
	}

	raw, err := os.ReadFile(ouiPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Updated Vendor") {
		t.Fatalf("oui.txt no fue actualizado: %q", raw)
	}

	db, err := loadBinDB(binPath)
	if err != nil {
		t.Fatalf("loadBinDB: %v", err)
	}
	got, ok := db.lookup([3]byte{0xAA, 0xBB, 0xCC})
	if !ok {
		t.Fatal("AABBCC no encontrado en oui.txt.bin regenerado")
	}
	if got != "Updated Vendor" {
		t.Fatalf("binary vendor = %q, expected Updated Vendor", got)
	}

	iabRaw, err := os.ReadFile(iabPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(iabRaw), "IAB Vendor") {
		t.Fatalf("iab.txt no fue actualizado: %q", iabRaw)
	}
}

func TestUpdateVendorFilesPropagatesDownloadError(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.txt")
	err := UpdateVendorFiles(filepath.Join(dir, "oui.txt"), filepath.Join(dir, "iab.txt"), "file://"+missing, "file://"+missing, 0)
	if err == nil {
		t.Fatal("esperaba error de descarga")
	}
}

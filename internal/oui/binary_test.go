package oui

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildAndLookupBinDB(t *testing.T) {
	src := map[string]string{
		"AABBCC": "Vendor Alpha",
		"001122": "Beta Networks",
		"FFEEDD": "Gamma Co.",
		"112233": "Delta Inc.",
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "oui.bin")
	if err := BuildBinFile(out, src); err != nil {
		t.Fatalf("BuildBinFile: %v", err)
	}
	st, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	expected := int64(binHeaderLen + len(src)*binEntrySize)
	if st.Size() != expected {
		t.Fatalf("size %d != expected %d", st.Size(), expected)
	}

	db, err := loadBinDB(out)
	if err != nil {
		t.Fatalf("loadBinDB: %v", err)
	}
	if db.count != len(src) {
		t.Fatalf("count = %d, expected %d", db.count, len(src))
	}

	cases := []struct {
		prefix [3]byte
		want   string
	}{
		{[3]byte{0x00, 0x11, 0x22}, "Beta Networks"},
		{[3]byte{0x11, 0x22, 0x33}, "Delta Inc."},
		{[3]byte{0xAA, 0xBB, 0xCC}, "Vendor Alpha"},
		{[3]byte{0xFF, 0xEE, 0xDD}, "Gamma Co."},
	}
	for _, c := range cases {
		got, ok := db.lookup(c.prefix)
		if !ok {
			t.Errorf("lookup(%v): not found", c.prefix)
			continue
		}
		if got != c.want {
			t.Errorf("lookup(%v) = %q, want %q", c.prefix, got, c.want)
		}
	}

	// Missing prefix.
	if got, ok := db.lookup([3]byte{0x12, 0x34, 0x56}); ok {
		t.Errorf("expected lookup miss, got %q", got)
	}
}

func TestLoadBinDBInvalid(t *testing.T) {
	dir := t.TempDir()

	// 1) Incorrect magic.
	bad := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(bad, []byte("XXXXXXXX"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBinDB(bad); err == nil {
		t.Error("invalid magic: expected error")
	}

	// 2) Missing file: not an error.
	missing := filepath.Join(dir, "missing.bin")
	db, err := loadBinDB(missing)
	if err != nil {
		t.Errorf("loadBinDB(missing) = %v, expected nil", err)
	}
	if db != nil {
		t.Errorf("loadBinDB(missing) = %v, expected nil", db)
	}
}

func BenchmarkBinDBLookup(b *testing.B) {
	src := make(map[string]string, 4096)
	for i := 0; i < 4096; i++ {
		key := []byte{
			"0123456789ABCDEF"[(i>>20)&15],
			"0123456789ABCDEF"[(i>>16)&15],
			"0123456789ABCDEF"[(i>>12)&15],
			"0123456789ABCDEF"[(i>>8)&15],
			"0123456789ABCDEF"[(i>>4)&15],
			"0123456789ABCDEF"[i&15],
		}
		src[string(key)] = "VendorX"
	}
	dir := b.TempDir()
	out := filepath.Join(dir, "oui.bin")
	if err := BuildBinFile(out, src); err != nil {
		b.Fatal(err)
	}
	db, err := loadBinDB(out)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	var sink string
	for i := 0; i < b.N; i++ {
		p := [3]byte{byte(i >> 16), byte(i >> 8), byte(i)}
		sink, _ = db.lookup(p)
	}
	_ = sink
}

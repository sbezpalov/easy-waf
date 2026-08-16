package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// buildCountryMMDB returns the raw bytes of a minimal country database.
func buildCountryMMDB(t *testing.T, dbType, ip, iso string) []byte {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: dbType,
		IPVersion:    4,
		RecordSize:   24,
		Inserter:     inserter.ReplaceWith,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, n, err := net.ParseCIDR(ip + "/32")
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Insert(n, mmdbtype.Map{
		"country": mmdbtype.Map{"iso_code": mmdbtype.String(iso)},
	}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := tree.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tarGz(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractAndInstallMMDB_rawFile(t *testing.T) {
	dir := t.TempDir()
	raw := buildCountryMMDB(t, "GeoLite2-Country", "8.8.8.8", "US")

	tmp, err := ExtractMMDB(bytes.NewReader(raw), dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	info, err := InstallMMDB(tmp, dir)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if info.Path != filepath.Join(dir, "GeoLite2-Country.mmdb") {
		t.Fatalf("unexpected install path %q", info.Path)
	}
	if info.ProbeCountry != "US" || info.DatabaseType != "GeoLite2-Country" {
		t.Fatalf("unexpected metadata: %+v", info)
	}
	if fi, err := os.Stat(info.Path); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("installed file mode: %v %v", fi, err)
	}
	// The temporary upload file must not survive installation.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".upload-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

// MaxMind publishes .tar.gz, so the archive path is the common case.
func TestExtractMMDB_tarGz(t *testing.T) {
	dir := t.TempDir()
	raw := buildCountryMMDB(t, "GeoLite2-Country", "8.8.8.8", "US")
	archive := tarGz(t, map[string][]byte{
		"GeoLite2-Country_20260816/COPYRIGHT.txt":         []byte("(c) MaxMind"),
		"GeoLite2-Country_20260816/GeoLite2-Country.mmdb": raw,
	})

	tmp, err := ExtractMMDB(bytes.NewReader(archive), dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	info, err := InstallMMDB(tmp, dir)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if info.ProbeCountry != "US" {
		t.Fatalf("probe country = %q", info.ProbeCountry)
	}
}

// A member name must never decide where bytes land: the extractor writes into
// its own temp file and ignores the archive's paths entirely.
func TestExtractMMDB_ignoresArchivePaths(t *testing.T) {
	dir := t.TempDir()
	raw := buildCountryMMDB(t, "GeoLite2-Country", "8.8.8.8", "US")
	archive := tarGz(t, map[string][]byte{
		"../../../../etc/easy-waf/evil.mmdb": raw,
	})

	tmp, err := ExtractMMDB(bytes.NewReader(archive), dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if filepath.Dir(tmp) != dir {
		t.Fatalf("wrote outside the destination directory: %s", tmp)
	}
	if _, err := os.Stat("/etc/easy-waf/evil.mmdb"); err == nil {
		t.Fatal("traversal member escaped the destination")
	}
	info, err := InstallMMDB(tmp, dir)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if filepath.Dir(info.Path) != dir {
		t.Fatalf("installed outside the destination directory: %s", info.Path)
	}
}

func TestExtractMMDB_rejectsJunk(t *testing.T) {
	dir := t.TempDir()

	// Not a database at all: extraction succeeds, validation must not.
	tmp, err := ExtractMMDB(strings.NewReader("this is not a database"), dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if _, err := InstallMMDB(tmp, dir); err == nil {
		t.Fatal("junk file installed as a database")
	}
	_ = os.Remove(tmp)

	// Empty body.
	if _, err := ExtractMMDB(strings.NewReader(""), dir); err == nil {
		t.Fatal("empty upload accepted")
	}

	// Archive without any .mmdb member.
	archive := tarGz(t, map[string][]byte{"readme.txt": []byte("nothing here")})
	if _, err := ExtractMMDB(bytes.NewReader(archive), dir); err == nil {
		t.Fatal("archive without a database accepted")
	}
}

// A gzip bomb must be stopped by the decompressed-size cap, not by disk space.
func TestExtractMMDB_capsDecompressedSize(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	huge := MaxMMDBBytes + (1 << 20)
	if err := tw.WriteHeader(&tar.Header{
		Name: "big.mmdb", Mode: 0o644, Size: huge, Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	for written := int64(0); written < huge; written += int64(len(chunk)) {
		if _, err := tw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = zw.Close()

	if _, err := ExtractMMDB(bytes.NewReader(buf.Bytes()), dir); err == nil {
		t.Fatal("oversized archive accepted")
	}
	// Nothing may be left behind after a rejected upload.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("rejected upload left %d files", len(entries))
	}
}

// A database that opens but cannot answer for the probe IP is useless as a
// GeoIP source and must not replace a working one.
func TestValidateMMDBFile_rejectsUnusableDatabase(t *testing.T) {
	dir := t.TempDir()
	raw := buildCountryMMDB(t, "GeoLite2-Country", "1.1.1.1", "AU")
	p := filepath.Join(dir, "no-probe.mmdb")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateMMDBFile(p); err == nil {
		t.Fatal("database without the probe address accepted")
	}

	// Wrong database type (e.g. an ASN database) has no country data.
	raw = buildCountryMMDB(t, "GeoLite2-ASN", "8.8.8.8", "US")
	p = filepath.Join(dir, "asn.mmdb")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateMMDBFile(p); err == nil {
		t.Fatal("ASN database accepted as a country source")
	}
}

// An existing database must survive a rejected upload.
func TestInstallMMDB_keepsPreviousDatabaseOnFailure(t *testing.T) {
	dir := t.TempDir()
	good := buildCountryMMDB(t, "GeoLite2-Country", "8.8.8.8", "US")
	live := filepath.Join(dir, "GeoLite2-Country.mmdb")
	if err := os.WriteFile(live, good, 0o644); err != nil {
		t.Fatal(err)
	}

	tmp, err := ExtractMMDB(strings.NewReader("garbage payload"), dir)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if _, err := InstallMMDB(tmp, dir); err == nil {
		t.Fatal("garbage installed")
	}
	current, err := os.ReadFile(live)
	if err != nil || !bytes.Equal(current, good) {
		t.Fatal("live database was modified by a failed upload")
	}
}

func TestInstalledMMDBName(t *testing.T) {
	cases := map[string]string{
		"GeoLite2-Country":       "GeoLite2-Country.mmdb",
		"GeoLite2-City":          "GeoLite2-City.mmdb",
		"":                       "GeoLite2-Country.mmdb",
		"../../etc/passwd":       "GeoLite2-Country.mmdb",
		"a/b":                    "GeoLite2-Country.mmdb",
		"with space":             "GeoLite2-Country.mmdb",
		strings.Repeat("x", 200): "GeoLite2-Country.mmdb",
	}
	for in, want := range cases {
		if got := InstalledMMDBName(in); got != want {
			t.Fatalf("InstalledMMDBName(%q) = %q, want %q", in, got, want)
		}
	}
}

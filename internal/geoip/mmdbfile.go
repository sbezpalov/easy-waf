// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

const (
	// MaxMMDBBytes caps an accepted database. GeoLite2-Country is a few MB and
	// GeoLite2-City is under 100 MB; anything larger is not a GeoLite2 database.
	MaxMMDBBytes int64 = 128 << 20
	// mmdbProbeIP is looked up to prove the database actually answers queries
	// before it replaces a working one.
	mmdbProbeIP = "8.8.8.8"
)

// safeDatabaseType matches the metadata field used to name the installed file.
// The value comes from an uploaded file, so it may never contain a path.
var safeDatabaseType = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// MMDBInfo describes a validated database file.
type MMDBInfo struct {
	Path         string    `json:"path"`
	DatabaseType string    `json:"database_type"`
	BuildEpoch   time.Time `json:"build_epoch"`
	NodeCount    uint      `json:"node_count"`
	IPVersion    uint      `json:"ip_version"`
	SizeBytes    int64     `json:"size_bytes"`
	ProbeIP      string    `json:"probe_ip"`
	ProbeCountry string    `json:"probe_country"`
}

// ValidateMMDBFile opens path as a MaxMind database and proves it can answer a
// lookup. Used before an uploaded file is allowed to replace the live database:
// a truncated or unrelated file must never become the active GeoIP source.
func ValidateMMDBFile(path string) (MMDBInfo, error) {
	info := MMDBInfo{Path: path, ProbeIP: mmdbProbeIP}

	st, err := os.Stat(path)
	if err != nil {
		return info, fmt.Errorf("mmdb: %w", err)
	}
	if !st.Mode().IsRegular() {
		return info, fmt.Errorf("mmdb: not a regular file")
	}
	info.SizeBytes = st.Size()

	rd, err := maxminddb.Open(path)
	if err != nil {
		return info, fmt.Errorf("mmdb: not a MaxMind database: %w", err)
	}
	defer rd.Close()

	info.DatabaseType = rd.Metadata.DatabaseType
	info.NodeCount = rd.Metadata.NodeCount
	info.IPVersion = rd.Metadata.IPVersion
	if be := rd.Metadata.BuildEpoch; be <= math.MaxInt64 {
		info.BuildEpoch = time.Unix(int64(be), 0).UTC()
	}

	if !strings.Contains(strings.ToLower(info.DatabaseType), "country") &&
		!strings.Contains(strings.ToLower(info.DatabaseType), "city") {
		return info, fmt.Errorf("mmdb: database type %q has no country data", info.DatabaseType)
	}

	var rec maxMindCountryRecord
	if err := rd.Lookup(net.ParseIP(mmdbProbeIP), &rec); err != nil {
		return info, fmt.Errorf("mmdb: probe lookup failed: %w", err)
	}
	info.ProbeCountry = rec.Country.ISOCode
	if info.ProbeCountry == "" {
		return info, fmt.Errorf("mmdb: probe lookup for %s returned no country", mmdbProbeIP)
	}
	return info, nil
}

// InstalledMMDBName derives the on-disk file name from the database metadata.
//
// The name is never taken from the request: an uploaded file must not be able to
// choose where it lands, so anything unexpected falls back to a fixed name.
func InstalledMMDBName(databaseType string) string {
	t := strings.TrimSpace(databaseType)
	if t == "" || !safeDatabaseType.MatchString(t) || strings.Contains(t, "..") {
		return "GeoLite2-Country.mmdb"
	}
	return t + ".mmdb"
}

// ExtractMMDB copies a database from src into dstDir and returns the temporary
// file path. src is either a raw .mmdb stream or a gzipped tar archive as
// published by MaxMind; the format is detected from the content, never from a
// client-supplied file name.
//
// The caller must remove the returned file if it decides not to install it.
func ExtractMMDB(src io.Reader, dstDir string) (string, error) {
	if err := os.MkdirAll(dstDir, 0o750); err != nil {
		return "", fmt.Errorf("mmdb: prepare directory: %w", err)
	}
	tmp, err := os.CreateTemp(dstDir, ".upload-*.mmdb")
	if err != nil {
		return "", fmt.Errorf("mmdb: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}

	// Peek at the magic bytes: 1f 8b marks gzip (MaxMind ships .tar.gz).
	head := make([]byte, 2)
	n, err := io.ReadFull(src, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		cleanup()
		return "", fmt.Errorf("mmdb: read input: %w", err)
	}
	head = head[:n]
	body := io.MultiReader(strings.NewReader(string(head)), src)

	if len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b {
		err = copyMMDBFromTarGz(body, tmp)
	} else {
		err = copyCapped(tmp, body)
	}
	if err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", fmt.Errorf("mmdb: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("mmdb: close: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("mmdb: chmod: %w", err)
	}
	return tmpPath, nil
}

// copyMMDBFromTarGz pulls the single *.mmdb member out of a MaxMind tarball.
// Only regular files are considered and nothing is written using a name from the
// archive, so neither path traversal nor a symlink member can escape dstDir.
func copyMMDBFromTarGz(r io.Reader, dst io.Writer) error {
	zr, err := gzip.NewReader(io.LimitReader(r, MaxMMDBBytes+1))
	if err != nil {
		return fmt.Errorf("mmdb: gzip: %w", err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("mmdb: archive contains no .mmdb file")
		}
		if err != nil {
			return fmt.Errorf("mmdb: tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		// Match on the base name only; the member path itself is never used.
		if !strings.EqualFold(filepath.Ext(filepath.Base(filepath.FromSlash(hdr.Name))), ".mmdb") {
			continue
		}
		return copyCapped(dst, tr)
	}
}

// copyCapped writes at most MaxMMDBBytes, refusing input that claims to be larger
// (a decompression bomb would otherwise fill the state directory).
func copyCapped(dst io.Writer, src io.Reader) error {
	written, err := io.Copy(dst, io.LimitReader(src, MaxMMDBBytes+1))
	if err != nil {
		return fmt.Errorf("mmdb: write: %w", err)
	}
	if written > MaxMMDBBytes {
		return fmt.Errorf("mmdb: database exceeds %d bytes", MaxMMDBBytes)
	}
	if written == 0 {
		return fmt.Errorf("mmdb: empty input")
	}
	return nil
}

// InstallMMDB validates tmpPath and, only if it is a working database, moves it
// over the target name inside dstDir. The rename is atomic within the directory,
// so a failed upload can never leave the appliance with a half-written database.
func InstallMMDB(tmpPath, dstDir string) (MMDBInfo, error) {
	info, err := ValidateMMDBFile(tmpPath)
	if err != nil {
		return info, err
	}
	dst := filepath.Join(dstDir, InstalledMMDBName(info.DatabaseType))
	if err := os.Rename(tmpPath, dst); err != nil {
		return info, fmt.Errorf("mmdb: install: %w", err)
	}
	info.Path = dst
	return info, nil
}

// ProbeCountry runs a country lookup through an already-open provider; used by
// callers that want a post-install sanity check against the live runtime.
func ProbeCountry(ctx context.Context, p GeoProvider, ip string) (string, error) {
	if p == nil {
		return "", fmt.Errorf("geoip: no provider")
	}
	return p.Lookup(ctx, ip)
}

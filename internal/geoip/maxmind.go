package geoip

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// MaxMindProvider resolves IPs using a local GeoLite2-Country (or compatible) MMDB file.
type MaxMindProvider struct {
	mu     sync.RWMutex
	reader *maxminddb.Reader
	path   string
}

type maxMindCountryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// NewMaxMindProvider opens dbPath (e.g. GeoLite2-Country.mmdb). The file must exist.
func NewMaxMindProvider(dbPath string) (*MaxMindProvider, error) {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		return nil, fmt.Errorf("geoip maxmind: empty database path")
	}
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("geoip maxmind: database file %q: %w", dbPath, err)
	}
	r, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("geoip maxmind: open %q: %w", dbPath, err)
	}
	return &MaxMindProvider{reader: r, path: dbPath}, nil
}

// Lookup returns ISO 3166-1 alpha-2 country code for a host IP.
func (p *MaxMindProvider) Lookup(ctx context.Context, ipStr string) (string, error) {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return "", fmt.Errorf("geoip: empty ip")
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("geoip: invalid ip %q", ipStr)
	}
	p.mu.RLock()
	rd := p.reader
	p.mu.RUnlock()
	if rd == nil {
		return "", fmt.Errorf("geoip maxmind: reader closed")
	}
	var rec maxMindCountryRecord
	if err := rd.Lookup(ip, &rec); err != nil {
		return "", fmt.Errorf("geoip maxmind: lookup %s: %w", ipStr, err)
	}
	cc := strings.ToUpper(strings.TrimSpace(rec.Country.ISOCode))
	if len(cc) != 2 {
		return "", fmt.Errorf("geoip maxmind: missing or invalid country for %s", ipStr)
	}
	_ = ctx // reader is synchronous; context reserved for future cancellation
	return cc, nil
}

// Reload opens a new reader from dbPath, swaps it under the lock, and closes the previous reader.
func (p *MaxMindProvider) Reload(dbPath string) error {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		return fmt.Errorf("geoip maxmind: empty database path for reload")
	}
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("geoip maxmind: database file %q: %w", dbPath, err)
	}
	nr, err := maxminddb.Open(dbPath)
	if err != nil {
		return fmt.Errorf("geoip maxmind: open %q: %w", dbPath, err)
	}
	p.mu.Lock()
	old := p.reader
	p.reader = nr
	p.path = dbPath
	p.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// Close releases the mmap / file handle.
func (p *MaxMindProvider) Close() error {
	p.mu.Lock()
	rd := p.reader
	p.reader = nil
	p.path = ""
	p.mu.Unlock()
	if rd == nil {
		return nil
	}
	return rd.Close()
}

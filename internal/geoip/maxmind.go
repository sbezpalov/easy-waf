// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

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
//
// The reader memory-maps the database, so a lookup must never run against a
// reader that Reload or Close has already unmapped: lookups hold mu for reading
// for their whole duration and retiring a reader takes mu exclusively.
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
	var rec maxMindCountryRecord
	p.mu.RLock()
	if p.reader == nil {
		p.mu.RUnlock()
		return "", fmt.Errorf("geoip maxmind: reader closed")
	}
	err := p.reader.Lookup(ip, &rec)
	p.mu.RUnlock()
	if err != nil {
		return "", fmt.Errorf("geoip maxmind: lookup %s: %w", ipStr, err)
	}
	cc := strings.ToUpper(strings.TrimSpace(rec.Country.ISOCode))
	if len(cc) != 2 {
		return "", fmt.Errorf("geoip maxmind: missing or invalid country for %s", ipStr)
	}
	_ = ctx // reader is synchronous; context reserved for future cancellation
	return cc, nil
}

// Reload opens a new reader from dbPath, swaps it in and closes the previous
// reader once no lookup is using it.
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
	defer p.mu.Unlock()
	old := p.reader
	p.reader = nr
	p.path = dbPath
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// Close releases the mmap / file handle once in-flight lookups have finished.
func (p *MaxMindProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	rd := p.reader
	p.reader = nil
	p.path = ""
	if rd == nil {
		return nil
	}
	return rd.Close()
}

// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"sync"
	"testing"

	"github.com/easy-waf/easy-waf/internal/config"
)

// API handlers change settings while an apply reads them; run under -race.
func TestSettingsAccessorsAreSafeForConcurrentUse(t *testing.T) {
	e := New(t.TempDir(), nil, config.DefaultSettings(t.TempDir()))
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				cfg := e.Settings()
				cfg.GeoIPEnabled = (i+j)%2 == 0
				e.SetSettings(cfg)
			}
		}(i)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = e.Settings().GeoIPEnabled
				if e.GeoIP() == nil {
					t.Error("GeoIP runtime is nil")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestGeoIPRuntimeIsCreatedOnce(t *testing.T) {
	e := New(t.TempDir(), nil, config.GlobalSettings{})
	first := e.GeoIP()
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.GeoIP() != first {
				t.Error("GeoIP runtime replaced")
			}
		}()
	}
	wg.Wait()
}

package haproxy

import (
	"bytes"
	"testing"
)

func TestAugmentGoldenHAProxyCfgForHaproxyCheck_idempotent(t *testing.T) {
	raw := []byte("frontend fe\n\tbind :80\n")
	once := augmentGoldenHAProxyCfgForHaproxyCheck(raw)
	if !bytes.Contains(once, []byte("backend crowdsec-socket")) {
		t.Fatal("expected SPOP backend appended")
	}
	twice := augmentGoldenHAProxyCfgForHaproxyCheck(once)
	if !bytes.Equal(once, twice) {
		t.Fatal("expected idempotent augment")
	}
}

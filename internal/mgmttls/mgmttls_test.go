package mgmttls

import (
	"testing"
)

func TestEnsureSelfSignedAndManager(t *testing.T) {
	stateDir := t.TempDir()
	certPath, keyPath, err := EnsureSelfSigned(stateDir)
	if err != nil {
		t.Fatalf("EnsureSelfSigned failed: %v", err)
	}

	expectedCertPath, expectedKeyPath := Paths(stateDir)
	if certPath != expectedCertPath || keyPath != expectedKeyPath {
		t.Errorf("Paths mismatch: got (%q, %q), want (%q, %q)", certPath, keyPath, expectedCertPath, expectedKeyPath)
	}

	// Calling EnsureSelfSigned again should be idempotent and return existing paths
	certPath2, keyPath2, err := EnsureSelfSigned(stateDir)
	if err != nil {
		t.Fatalf("EnsureSelfSigned 2nd call failed: %v", err)
	}
	if certPath2 != certPath || keyPath2 != keyPath {
		t.Errorf("EnsureSelfSigned non-idempotent: got (%q, %q), want (%q, %q)", certPath2, keyPath2, certPath, keyPath)
	}

	// Test Manager
	var mgr Manager
	_, err = mgr.GetCertificate(nil)
	if err == nil {
		t.Errorf("GetCertificate on empty Manager should error")
	}

	if err := mgr.LoadFromFiles(certPath, keyPath); err != nil {
		t.Fatalf("LoadFromFiles failed: %v", err)
	}

	cert, err := mgr.GetCertificate(nil)
	if err != nil || cert == nil {
		t.Fatalf("GetCertificate after LoadFromFiles failed: %v", err)
	}
}

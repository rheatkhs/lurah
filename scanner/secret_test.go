package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanSecrets_DebugTrueProduction(t *testing.T) {
	dir := t.TempDir()
	envContent := "APP_NAME=Test\nAPP_ENV=production\nAPP_DEBUG=true\nAPP_KEY=base64:abc123\n"
	os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0644)

	findings := ScanSecrets(dir)

	found := false
	for _, f := range findings {
		if f.Severity == CRITICAL && f.Line == 3 {
			found = true
		}
	}
	if !found {
		t.Error("Expected CRITICAL finding for APP_DEBUG=true in production, got none")
	}
}

func TestScanSecrets_DebugTrueLocal(t *testing.T) {
	dir := t.TempDir()
	envContent := "APP_ENV=local\nAPP_DEBUG=true\nAPP_KEY=base64:abc123\n"
	os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0644)

	findings := ScanSecrets(dir)

	for _, f := range findings {
		if f.Severity == CRITICAL && f.File == filepath.Join(dir, ".env") &&
			f.Line == 2 {
			t.Error("APP_DEBUG=true should NOT be flagged in local environment")
		}
	}
}

func TestScanSecrets_EmptyAppKey(t *testing.T) {
	dir := t.TempDir()
	envContent := "APP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=\n"
	os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0644)

	findings := ScanSecrets(dir)

	found := false
	for _, f := range findings {
		if f.Severity == CRITICAL && f.Line == 3 {
			found = true
		}
	}
	if !found {
		t.Error("Expected CRITICAL finding for empty APP_KEY, got none")
	}
}

func TestScanSecrets_NoEnvFile(t *testing.T) {
	dir := t.TempDir()
	findings := ScanSecrets(dir)

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for missing .env, got %d", len(findings))
	}
}

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanCSRF_WildcardExclusion(t *testing.T) {
	dir := t.TempDir()
	mwDir := filepath.Join(dir, "app", "Http", "Middleware")
	os.MkdirAll(mwDir, 0755)

	phpContent := `<?php
namespace App\Http\Middleware;

class VerifyCsrfToken extends Middleware
{
    protected $except = [
        'api/*',
        'webhook/stripe',
    ];
}
`
	os.WriteFile(filepath.Join(mwDir, "VerifyCsrfToken.php"), []byte(phpContent), 0644)

	findings := ScanCSRF(dir)

	hasHigh := false
	for _, f := range findings {
		if f.Severity == HIGH {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Error("Expected HIGH finding for wildcard CSRF exclusion 'api/*'")
	}
}

func TestScanCSRF_SpecificRoute(t *testing.T) {
	dir := t.TempDir()
	mwDir := filepath.Join(dir, "app", "Http", "Middleware")
	os.MkdirAll(mwDir, 0755)

	phpContent := `<?php
namespace App\Http\Middleware;

class VerifyCsrfToken extends Middleware
{
    protected $except = [
        'webhook/stripe',
    ];
}
`
	os.WriteFile(filepath.Join(mwDir, "VerifyCsrfToken.php"), []byte(phpContent), 0644)

	findings := ScanCSRF(dir)

	for _, f := range findings {
		if f.Severity == HIGH {
			t.Error("Specific route exclusion should NOT trigger HIGH finding")
		}
	}
}

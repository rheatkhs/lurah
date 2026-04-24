package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanSQLInjection_DBRaw(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "app", "Models")
	os.MkdirAll(appDir, 0755)

	phpContent := `<?php
namespace App\Models;

class Report extends Model
{
    public function scopeFilter($query, $filter)
    {
        return $query->whereRaw("status = '$filter'");
    }
}
`
	os.WriteFile(filepath.Join(appDir, "Report.php"), []byte(phpContent), 0644)

	findings := ScanSQLInjection(dir)

	hasCritical := false
	for _, f := range findings {
		if f.Severity == CRITICAL {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("Expected CRITICAL finding for whereRaw with variable interpolation")
	}
}

func TestScanSQLInjection_SafeQuery(t *testing.T) {
	dir := t.TempDir()
	appDir := filepath.Join(dir, "app", "Models")
	os.MkdirAll(appDir, 0755)

	phpContent := `<?php
namespace App\Models;

class Report extends Model
{
    public function scopeFilter($query, $filter)
    {
        return $query->where('status', $filter);
    }
}
`
	os.WriteFile(filepath.Join(appDir, "Report.php"), []byte(phpContent), 0644)

	findings := ScanSQLInjection(dir)

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for safe Eloquent query, got %d", len(findings))
	}
}

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanPII_FunctionScopeJSON(t *testing.T) {
	dir := t.TempDir()
	controllerDir := filepath.Join(dir, "app", "Http", "Controllers")
	os.MkdirAll(controllerDir, 0755)

	phpContent := `<?php
namespace App\Http\Controllers;

class WargaController extends Controller
{
    public function show($id)
    {
        $nik = '3201234567890001';
        $nama = 'John Doe';

        return response()->json([
            'nik' => $nik,
            'nama' => $nama,
        ]);
    }
}
`
	os.WriteFile(filepath.Join(controllerDir, "WargaController.php"), []byte(phpContent), 0644)

	findings := ScanPII(dir)

	hasHigh := false
	for _, f := range findings {
		if f.Severity == HIGH {
			hasHigh = true
		}
	}
	if !hasHigh {
		t.Error("Expected HIGH finding for $nik in function with JSON response")
	}
}

func TestScanPII_NoJSON(t *testing.T) {
	dir := t.TempDir()
	controllerDir := filepath.Join(dir, "app", "Http", "Controllers")
	os.MkdirAll(controllerDir, 0755)

	phpContent := `<?php
namespace App\Http\Controllers;

class InternalController extends Controller
{
    public function process()
    {
        $nik = request()->input('nik');
        $result = $this->service->validate($nik);
        return view('result', compact('result'));
    }
}
`
	os.WriteFile(filepath.Join(controllerDir, "InternalController.php"), []byte(phpContent), 0644)

	findings := ScanPII(dir)

	for _, f := range findings {
		if f.Severity == HIGH {
			t.Error("Should NOT produce HIGH finding when no JSON response in function")
		}
	}

	hasMedium := false
	for _, f := range findings {
		if f.Severity == MEDIUM {
			hasMedium = true
		}
	}
	if !hasMedium {
		t.Error("Expected MEDIUM finding for $nik detected in function")
	}
}

func TestScanPII_NoControllerDir(t *testing.T) {
	dir := t.TempDir()
	findings := ScanPII(dir)

	if len(findings) != 0 {
		t.Errorf("Expected 0 findings when no Controllers directory exists, got %d", len(findings))
	}
}

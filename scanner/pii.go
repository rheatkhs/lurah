package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// piiPatterns are PII variable names that must be masked before API output.
var piiPatterns = []string{"nik", "npwp", "rekening"}

// jsonResponsePattern matches common Laravel JSON response patterns.
var jsonResponsePattern = regexp.MustCompile(`(?i)(response\(\)\s*->\s*json|return\s+.*json|->toArray|Resource::collection|JsonResponse)`)

// piiVarPattern builds a regex to match PHP variable usage like $nik, $npwp, $rekening.
func piiVarRegex(name string) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`(?i)\$%s\b`, regexp.QuoteMeta(name)))
}

// ScanPII walks the Controllers directory looking for PII variables
// returned in raw JSON responses.
func ScanPII(projectPath string) []Finding {
	var findings []Finding

	// Laravel controller paths (handle both lowercase and Pascal case)
	controllerDirs := []string{
		filepath.Join(projectPath, "app", "Http", "Controllers"),
		filepath.Join(projectPath, "app", "http", "controllers"),
	}

	var controllerDir string
	for _, dir := range controllerDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			controllerDir = dir
			break
		}
	}

	if controllerDir == "" {
		return findings
	}

	// Walk all .php files recursively
	_ = filepath.Walk(controllerDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable files
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".php") {
			return nil
		}

		fileFindings := scanPHPFile(path)
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings
}

// scanPHPFile scans a single PHP file for PII variable usage.
func scanPHPFile(filePath string) []Finding {
	var findings []Finding

	file, err := os.Open(filePath)
	if err != nil {
		return findings
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, pii := range piiPatterns {
			re := piiVarRegex(pii)
			if !re.MatchString(line) {
				continue
			}

			// Check if this line also has a JSON response pattern
			if jsonResponsePattern.MatchString(line) {
				findings = append(findings, Finding{
					Severity: HIGH,
					File:     filePath,
					Line:     lineNum,
					Recommendation: fmt.Sprintf(
						"PII variable '$%s' returned in raw JSON response. "+
							"Apply data masking before output (SPBE-PD.01).", pii),
				})
			} else {
				findings = append(findings, Finding{
					Severity: MEDIUM,
					File:     filePath,
					Line:     lineNum,
					Recommendation: fmt.Sprintf(
						"PII variable '$%s' detected. "+
							"Ensure it is masked before any API response (SPBE-PD.01).", pii),
				})
			}
		}
	}

	return findings
}

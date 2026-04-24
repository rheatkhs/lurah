package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SQL injection patterns to detect in PHP code.
var sqliPatterns = []*regexp.Regexp{
	// DB::raw() with variable interpolation
	regexp.MustCompile(`(?i)DB\s*::\s*raw\s*\(\s*["'].*\$`),
	regexp.MustCompile(`(?i)DB\s*::\s*raw\s*\(\s*\$`),

	// String concatenation in queries
	regexp.MustCompile(`(?i)DB\s*::\s*select\s*\(.*\.\s*\$`),
	regexp.MustCompile(`(?i)DB\s*::\s*statement\s*\(.*\.\s*\$`),
	regexp.MustCompile(`(?i)DB\s*::\s*insert\s*\(.*\.\s*\$`),
	regexp.MustCompile(`(?i)DB\s*::\s*update\s*\(.*\.\s*\$`),
	regexp.MustCompile(`(?i)DB\s*::\s*delete\s*\(.*\.\s*\$`),

	// whereRaw / havingRaw / orderByRaw with variables
	regexp.MustCompile(`(?i)->\s*whereRaw\s*\(\s*["'].*\$`),
	regexp.MustCompile(`(?i)->\s*whereRaw\s*\(\s*\$`),
	regexp.MustCompile(`(?i)->\s*havingRaw\s*\(\s*["'].*\$`),
	regexp.MustCompile(`(?i)->\s*orderByRaw\s*\(\s*["'].*\$`),
	regexp.MustCompile(`(?i)->\s*selectRaw\s*\(\s*["'].*\$`),

	// Direct PDO query with concatenation
	regexp.MustCompile(`(?i)\$pdo\s*->\s*query\s*\(.*\.\s*\$`),
	regexp.MustCompile(`(?i)\$pdo\s*->\s*exec\s*\(.*\.\s*\$`),
}

// ScanSQLInjection walks PHP files looking for potential SQL injection patterns.
func ScanSQLInjection(projectPath string) []Finding {
	var findings []Finding

	// Scan app/ directory recursively
	appDir := filepath.Join(projectPath, "app")
	if _, err := os.Stat(appDir); os.IsNotExist(err) {
		return findings
	}

	_ = filepath.Walk(appDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".php") {
			return nil
		}

		fileFindings := scanFileForSQLi(path)
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings
}

func scanFileForSQLi(filePath string) []Finding {
	var findings []Finding

	file, err := os.Open(filePath)
	if err != nil {
		return findings
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := sc.Text()

		for _, pattern := range sqliPatterns {
			if pattern.MatchString(line) {
				findings = append(findings, Finding{
					Severity: CRITICAL,
					File:     filePath,
					Line:     lineNum,
					Recommendation: fmt.Sprintf(
						"Potential SQL injection: raw query with variable interpolation detected. "+
							"Use parameterized queries or Eloquent bindings instead (SPBE-SI.04)."),
				})
				break // one finding per line
			}
		}
	}

	return findings
}

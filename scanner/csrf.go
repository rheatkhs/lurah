package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// csrfExceptPattern matches entries in the $except array of VerifyCsrfToken.
var csrfExceptPattern = regexp.MustCompile(`(?i)['"]([^'"]+)['"]`)

// ScanCSRF checks the VerifyCsrfToken middleware for overly broad CSRF exclusions.
func ScanCSRF(projectPath string) []Finding {
	var findings []Finding

	// Possible locations for CSRF middleware
	csrfPaths := []string{
		filepath.Join(projectPath, "app", "Http", "Middleware", "VerifyCsrfToken.php"),
		filepath.Join(projectPath, "app", "http", "middleware", "VerifyCsrfToken.php"),
	}

	var csrfFile string
	for _, p := range csrfPaths {
		if _, err := os.Stat(p); err == nil {
			csrfFile = p
			break
		}
	}

	if csrfFile == "" {
		return findings
	}

	file, err := os.Open(csrfFile)
	if err != nil {
		return findings
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	lineNum := 0
	inExcept := false
	wildcardPatterns := []string{"*", "/*", "api/*", "webhook/*"}

	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())

		// Detect the $except array
		if strings.Contains(line, "$except") && strings.Contains(line, "=") {
			inExcept = true
		}

		if inExcept {
			// Check for wildcard or overly broad patterns
			matches := csrfExceptPattern.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) < 2 {
					continue
				}
				route := match[1]

				for _, wc := range wildcardPatterns {
					if route == wc {
						findings = append(findings, Finding{
							Severity: HIGH,
							File:     csrfFile,
							Line:     lineNum,
							Recommendation: fmt.Sprintf(
								"CSRF protection disabled for broad pattern '%s'. "+
									"Narrow the exclusion to specific webhook endpoints only (SPBE-SI.05).", route),
						})
						break
					}
				}
			}

			// Check for closing bracket
			if strings.Contains(line, "];") || strings.Contains(line, ")") {
				countExceptions := 0
				// Recount all exceptions
				file2, err := os.Open(csrfFile)
				if err == nil {
					sc2 := bufio.NewScanner(file2)
					inExcept2 := false
					for sc2.Scan() {
						l := strings.TrimSpace(sc2.Text())
						if strings.Contains(l, "$except") && strings.Contains(l, "=") {
							inExcept2 = true
						}
						if inExcept2 {
							m := csrfExceptPattern.FindAllStringSubmatch(l, -1)
							countExceptions += len(m)
							if strings.Contains(l, "];") {
								break
							}
						}
					}
					file2.Close()
				}

				if countExceptions > 5 {
					findings = append(findings, Finding{
						Severity: MEDIUM,
						File:     csrfFile,
						Line:     lineNum,
						Recommendation: fmt.Sprintf(
							"CSRF has %d route exclusions. Review if all are necessary — "+
								"excessive exclusions weaken CSRF protection.", countExceptions),
					})
				}
				inExcept = false
			}
		}
	}

	return findings
}

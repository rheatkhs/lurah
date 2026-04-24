package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ScanSecrets checks the .env file for insecure configurations.
// It flags APP_DEBUG=true unless the environment is "local".
func ScanSecrets(projectPath string) []Finding {
	var findings []Finding

	envPath := filepath.Join(projectPath, ".env")

	file, err := os.Open(envPath)
	if err != nil {
		// .env not found — nothing to scan
		return findings
	}
	defer file.Close()

	var (
		appDebug    *Finding
		appEnv      string
		debugLine   int
	)

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch strings.ToUpper(key) {
		case "APP_DEBUG":
			if strings.EqualFold(value, "true") {
				debugLine = lineNum
				finding := Finding{
					Severity: CRITICAL,
					File:     envPath,
					Line:     debugLine,
					Recommendation: "APP_DEBUG is true in a non-local environment. " +
						"Disable debug mode for production/staging to prevent sensitive data leaks (SPBE-SI.03).",
				}
				appDebug = &finding
			}
		case "APP_ENV":
			appEnv = strings.ToLower(value)
		}
	}

	// Only flag APP_DEBUG=true if the environment is NOT local
	if appDebug != nil && appEnv != "local" {
		findings = append(findings, *appDebug)
	}

	// Warn if APP_KEY is empty
	file2, err := os.Open(envPath)
	if err == nil {
		defer file2.Close()
		scanner2 := bufio.NewScanner(file2)
		ln := 0
		for scanner2.Scan() {
			ln++
			line := strings.TrimSpace(scanner2.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if strings.ToUpper(key) == "APP_KEY" && value == "" {
				findings = append(findings, Finding{
					Severity:       CRITICAL,
					File:           envPath,
					Line:           ln,
					Recommendation: fmt.Sprintf("APP_KEY is empty. Run 'php artisan key:generate' to set an encryption key (SPBE-SI.02)."),
				})
			}
		}
	}

	return findings
}

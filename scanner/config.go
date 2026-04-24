package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// configDebugPattern matches hardcoded debug => true in config files.
var configDebugPattern = regexp.MustCompile(`(?i)['"]debug['"]\s*=>\s*true`)

// configCleartext matches potential hardcoded credentials in config files.
var configCleartextPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)['"]password['"]\s*=>\s*['"][^'"]+['"]`),
	regexp.MustCompile(`(?i)['"]secret['"]\s*=>\s*['"][^'"]+['"]`),
	regexp.MustCompile(`(?i)['"]api_key['"]\s*=>\s*['"][^'"]+['"]`),
}

// envCallPattern matches env() calls — values using env() are acceptable.
var envCallPattern = regexp.MustCompile(`(?i)env\s*\(`)

// ScanConfig checks Laravel config files for hardcoded insecure values.
func ScanConfig(projectPath string) []Finding {
	var findings []Finding

	configDir := filepath.Join(projectPath, "config")
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		return findings
	}

	_ = filepath.Walk(configDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".php") {
			return nil
		}

		fileFindings := scanConfigFile(path)
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings
}

func scanConfigFile(filePath string) []Finding {
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

		// Skip lines that use env() — those are safe
		if envCallPattern.MatchString(line) {
			continue
		}

		// Check for hardcoded debug => true
		if configDebugPattern.MatchString(line) {
			findings = append(findings, Finding{
				Severity: HIGH,
				File:     filePath,
				Line:     lineNum,
				Recommendation: "Hardcoded 'debug' => true in config file. " +
					"Use env('APP_DEBUG', false) instead to respect environment (SPBE-SI.03).",
			})
		}

		// Check for hardcoded credentials
		for _, pattern := range configCleartextPatterns {
			if pattern.MatchString(line) {
				findings = append(findings, Finding{
					Severity: HIGH,
					File:     filePath,
					Line:     lineNum,
					Recommendation: fmt.Sprintf(
						"Hardcoded credential detected in config. "+
							"Use env() to load secrets from environment variables (SPBE-SI.02)."),
				})
				break
			}
		}
	}

	return findings
}

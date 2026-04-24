package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// knownVulnerablePackages is a curated list of Laravel ecosystem packages
// with known critical vulnerabilities. In production, this would be fetched
// from an advisory database.
var knownVulnerablePackages = map[string]struct {
	MaxSafeVersion string
	Advisory       string
}{
	"laravel/framework": {
		MaxSafeVersion: "8.83.27",
		Advisory:       "Multiple security fixes. Update to the latest LTS version.",
	},
	"phanan/koel": {
		MaxSafeVersion: "5.1.4",
		Advisory:       "Remote code execution vulnerability.",
	},
	"barryvdh/laravel-debugbar": {
		MaxSafeVersion: "",
		Advisory:       "Debug toolbar should NOT be installed in production. Remove from 'require' or move to 'require-dev'.",
	},
	"itsgoingd/clockwork": {
		MaxSafeVersion: "",
		Advisory:       "Debug profiler should NOT be installed in production. Remove from 'require' or move to 'require-dev'.",
	},
}

// composerLock represents the minimal structure of a composer.lock file.
type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ScanDependencies checks composer.lock for known vulnerable or debug packages.
func ScanDependencies(projectPath string) []Finding {
	var findings []Finding

	lockPath := filepath.Join(projectPath, "composer.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return findings
	}

	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		findings = append(findings, Finding{
			Severity:       MEDIUM,
			File:           lockPath,
			Line:           1,
			Recommendation: "composer.lock is malformed and cannot be parsed. Run 'composer install' to regenerate.",
		})
		return findings
	}

	// Check production packages for known vulnerabilities
	for _, pkg := range lock.Packages {
		if vuln, ok := knownVulnerablePackages[pkg.Name]; ok {
			findings = append(findings, Finding{
				Severity: HIGH,
				File:     lockPath,
				Line:     1,
				Recommendation: fmt.Sprintf(
					"Package '%s' (v%s) flagged: %s",
					pkg.Name, pkg.Version, vuln.Advisory),
			})
		}
	}

	// Check if debug packages leaked into production dependencies
	debugPackages := []string{
		"barryvdh/laravel-debugbar",
		"itsgoingd/clockwork",
		"laravel/telescope",
	}
	for _, pkg := range lock.Packages {
		for _, debugPkg := range debugPackages {
			if strings.EqualFold(pkg.Name, debugPkg) {
				findings = append(findings, Finding{
					Severity: HIGH,
					File:     lockPath,
					Line:     1,
					Recommendation: fmt.Sprintf(
						"Debug package '%s' is in production dependencies. "+
							"Move to 'require-dev' in composer.json (SPBE-SI.03).", pkg.Name),
				})
			}
		}
	}

	// Check for outdated PHP requirement
	composerPath := filepath.Join(projectPath, "composer.json")
	if cdata, err := os.ReadFile(composerPath); err == nil {
		var cj map[string]interface{}
		if json.Unmarshal(cdata, &cj) == nil {
			if req, ok := cj["require"].(map[string]interface{}); ok {
				if phpVer, ok := req["php"].(string); ok {
					if strings.Contains(phpVer, "7.") && !strings.Contains(phpVer, "8.") {
						findings = append(findings, Finding{
							Severity: MEDIUM,
							File:     composerPath,
							Line:     1,
							Recommendation: fmt.Sprintf(
								"PHP requirement '%s' targets PHP 7.x which is EOL. "+
									"Upgrade to PHP 8.1+ for continued security patches.", phpVer),
						})
					}
				}
			}
		}
	}

	return findings
}

// ScanEnvDiff compares .env against .env.example to find missing or placeholder keys.
func ScanEnvDiff(projectPath string) []Finding {
	var findings []Finding

	envPath := filepath.Join(projectPath, ".env")
	examplePath := filepath.Join(projectPath, ".env.example")

	envVars := parseEnvFile(envPath)
	exampleVars := parseEnvFile(examplePath)

	if len(exampleVars) == 0 {
		return findings
	}

	// Find keys in .env.example that are missing from .env
	for key, exLine := range exampleVars {
		if _, exists := envVars[key]; !exists {
			findings = append(findings, Finding{
				Severity: MEDIUM,
				File:     envPath,
				Line:     exLine.line,
				Recommendation: fmt.Sprintf(
					"Key '%s' exists in .env.example but is missing from .env. "+
						"This may cause runtime errors.", key),
			})
		}
	}

	// Find placeholder values in .env
	placeholders := []string{"xxxxxxxx", "your-", "change-me", "placeholder", "INSERT_", "TODO"}
	for key, val := range envVars {
		for _, ph := range placeholders {
			if strings.Contains(strings.ToLower(val.value), strings.ToLower(ph)) {
				findings = append(findings, Finding{
					Severity: MEDIUM,
					File:     envPath,
					Line:     val.line,
					Recommendation: fmt.Sprintf(
						"Key '%s' contains placeholder value '%s'. Replace with actual configuration.", key, val.value),
				})
				break
			}
		}
	}

	return findings
}

type envEntry struct {
	value string
	line  int
}

func parseEnvFile(path string) map[string]envEntry {
	result := make(map[string]envEntry)

	file, err := os.Open(path)
	if err != nil {
		return result
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		result[key] = envEntry{value: value, line: lineNum}
	}

	return result
}

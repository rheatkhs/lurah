package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// authGuardPattern matches auth guard configuration.
var authGuardPattern = regexp.MustCompile(`(?i)['"]guards['"]\s*=>`)

// sessionDriverPattern matches session driver configuration.
var sessionDriverPattern = regexp.MustCompile(`(?i)['"]driver['"]\s*=>\s*['"](\w+)['"]`)

// ScanAuth checks authentication configuration for security issues.
func ScanAuth(projectPath string) []Finding {
	var findings []Finding

	// Check config/auth.php
	authConfig := filepath.Join(projectPath, "config", "auth.php")
	if _, err := os.Stat(authConfig); err == nil {
		findings = append(findings, scanAuthConfig(authConfig)...)
	}

	// Check config/session.php
	sessionConfig := filepath.Join(projectPath, "config", "session.php")
	if _, err := os.Stat(sessionConfig); err == nil {
		findings = append(findings, scanSessionConfig(sessionConfig)...)
	}

	// Check for custom auth logic bypassing Laravel's system
	findings = append(findings, scanCustomAuth(projectPath)...)

	return findings
}

func scanAuthConfig(filePath string) []Finding {
	var findings []Finding

	data, err := os.ReadFile(filePath)
	if err != nil {
		return findings
	}
	content := string(data)

	// Check for insecure password hashing
	if regexp.MustCompile(`(?i)['"]driver['"]\s*=>\s*['"]md5['"]`).MatchString(content) ||
		regexp.MustCompile(`(?i)['"]driver['"]\s*=>\s*['"]sha1['"]`).MatchString(content) {

		findings = append(findings, Finding{
			Severity: CRITICAL,
			File:     filePath,
			Line:     1,
			Recommendation: "Insecure password hashing algorithm detected (md5/sha1). " +
				"Use bcrypt or argon2id for password hashing (SPBE-SI.01).",
		})
	}

	// Check for token-based guard without proper driver
	if strings.Contains(content, "'token'") &&
		!strings.Contains(content, "sanctum") &&
		!strings.Contains(content, "passport") {
		findings = append(findings, Finding{
			Severity: MEDIUM,
			File:     filePath,
			Line:     1,
			Recommendation: "Using basic token guard without Sanctum or Passport. " +
				"Consider using Laravel Sanctum for API token authentication with scoping and revocation.",
		})
	}

	return findings
}

func scanSessionConfig(filePath string) []Finding {
	var findings []Finding

	file, err := os.Open(filePath)
	if err != nil {
		return findings
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	lineNum := 0

	var (
		hasHttpOnly   bool
		hasSecure     bool
		hasSameSite   bool
		sessionDriver string
	)

	for sc.Scan() {
		lineNum++
		line := sc.Text()
		lower := strings.ToLower(line)

		// Check session driver
		if m := sessionDriverPattern.FindStringSubmatch(line); len(m) > 1 && sessionDriver == "" {
			sessionDriver = strings.ToLower(m[1])
		}

		// Check cookie security flags
		if strings.Contains(lower, "'http_only'") && strings.Contains(lower, "true") {
			hasHttpOnly = true
		}
		if strings.Contains(lower, "'secure'") && strings.Contains(lower, "true") {
			hasSecure = true
		}
		if strings.Contains(lower, "'same_site'") {
			if strings.Contains(lower, "'strict'") || strings.Contains(lower, "'lax'") {
				hasSameSite = true
			}
		}
	}

	// Check for insecure session driver
	if sessionDriver == "file" || sessionDriver == "cookie" {
		findings = append(findings, Finding{
			Severity: MEDIUM,
			File:     filePath,
			Line:     1,
			Recommendation: "Session driver '" + sessionDriver + "' is not recommended for production. " +
				"Use 'database', 'redis', or 'memcached' for better security and scalability.",
		})
	}

	if !hasHttpOnly {
		findings = append(findings, Finding{
			Severity: HIGH,
			File:     filePath,
			Line:     1,
			Recommendation: "Session cookie 'http_only' is not set to true. " +
				"Enable HttpOnly to prevent JavaScript access to session cookies (SPBE-SI.01).",
		})
	}

	if !hasSecure {
		findings = append(findings, Finding{
			Severity: MEDIUM,
			File:     filePath,
			Line:     1,
			Recommendation: "Session cookie 'secure' flag is not set to true. " +
				"Enable it to ensure cookies are only sent over HTTPS.",
		})
	}

	if !hasSameSite {
		findings = append(findings, Finding{
			Severity: MEDIUM,
			File:     filePath,
			Line:     1,
			Recommendation: "Session 'same_site' is not set to 'strict' or 'lax'. " +
				"Configure SameSite to prevent CSRF via cross-origin requests.",
		})
	}

	return findings
}

// customAuthPatterns detect hand-rolled auth logic that bypasses Laravel's system.
var customAuthPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)md5\s*\(\s*\$.*password`),
	regexp.MustCompile(`(?i)sha1\s*\(\s*\$.*password`),
	regexp.MustCompile(`(?i)password_verify\s*\(`),
	regexp.MustCompile(`(?i)Hash\s*::\s*check\s*\(`),
}

func scanCustomAuth(projectPath string) []Finding {
	var findings []Finding

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

		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		sc := bufio.NewScanner(file)
		lineNum := 0

		for sc.Scan() {
			lineNum++
			line := sc.Text()

			// Detect md5/sha1 password hashing
			if regexp.MustCompile(`(?i)md5\s*\(\s*\$.*password`).MatchString(line) ||
				regexp.MustCompile(`(?i)sha1\s*\(\s*\$.*password`).MatchString(line) {
				findings = append(findings, Finding{
					Severity: CRITICAL,
					File:     path,
					Line:     lineNum,
					Recommendation: "Insecure password hashing (md5/sha1) detected. " +
						"Use Hash::make() or bcrypt() for password hashing (SPBE-SI.01).",
				})
			}
		}

		return nil
	})

	return findings
}

package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// middlewareGroupPattern matches Route::middleware('auth') and similar.
var middlewareGroupPattern = regexp.MustCompile(`(?i)Route\s*::\s*middleware\s*\(\s*\[?([^)]+)\]?\s*\)`)

// routeMethodPattern matches Route::get/post/put/delete/patch/any.
var routeMethodPattern = regexp.MustCompile(`(?i)Route\s*::\s*(get|post|put|delete|patch|any)\s*\(`)

// sensitiveRoutePatterns are URI patterns that should have auth/throttle middleware.
var sensitiveRoutePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)['"]/?admin`),
	regexp.MustCompile(`(?i)['"]/?user`),
	regexp.MustCompile(`(?i)['"]/?profile`),
	regexp.MustCompile(`(?i)['"]/?account`),
	regexp.MustCompile(`(?i)['"]/?password`),
	regexp.MustCompile(`(?i)['"]/?setting`),
	regexp.MustCompile(`(?i)['"]/?payment`),
	regexp.MustCompile(`(?i)['"]/?order`),
	regexp.MustCompile(`(?i)['"]/?dashboard`),
	regexp.MustCompile(`(?i)['"]/?api/`),
}

// ScanMiddleware checks route files for missing auth and throttle middleware on sensitive routes.
func ScanMiddleware(projectPath string) []Finding {
	var findings []Finding

	routeFiles := []string{
		filepath.Join(projectPath, "routes", "api.php"),
		filepath.Join(projectPath, "routes", "web.php"),
	}

	for _, rf := range routeFiles {
		if _, err := os.Stat(rf); os.IsNotExist(err) {
			continue
		}
		fileFindings := scanRouteFile(rf)
		findings = append(findings, fileFindings...)
	}

	return findings
}

func scanRouteFile(filePath string) []Finding {
	var findings []Finding

	file, err := os.Open(filePath)
	if err != nil {
		return findings
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	lineNum := 0
	inAuthGroup := false
	groupDepth := 0

	// Track if we're inside a Route::middleware(['auth']) group
	for sc.Scan() {
		lineNum++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		// Detect middleware group
		if middlewareGroupPattern.MatchString(trimmed) {
			match := middlewareGroupPattern.FindStringSubmatch(trimmed)
			if len(match) > 1 {
				middlewares := strings.ToLower(match[1])
				if strings.Contains(middlewares, "auth") {
					inAuthGroup = true
					groupDepth = 0
				}
			}
		}

		// Track group nesting
		groupDepth += strings.Count(trimmed, "{")
		groupDepth -= strings.Count(trimmed, "}")
		if inAuthGroup && groupDepth <= 0 {
			inAuthGroup = false
		}

		// Check if this line defines a route
		if !routeMethodPattern.MatchString(trimmed) {
			continue
		}

		// Skip if inside an auth middleware group
		if inAuthGroup {
			continue
		}

		// Check if this route matches sensitive patterns
		for _, pattern := range sensitiveRoutePatterns {
			if pattern.MatchString(trimmed) {
				// Check if this specific route has inline middleware
				hasInlineAuth := strings.Contains(strings.ToLower(trimmed), "middleware") &&
					strings.Contains(strings.ToLower(trimmed), "auth")

				if !hasInlineAuth {
					findings = append(findings, Finding{
						Severity: HIGH,
						File:     filePath,
						Line:     lineNum,
						Recommendation: fmt.Sprintf(
							"Sensitive route lacks 'auth' middleware. "+
								"Add authentication middleware to protect this endpoint (SPBE-SI.01)."),
					})
				}
				break
			}
		}

		// Check API routes for rate limiting
		if strings.Contains(filePath, "api.php") {
			hasThrottle := strings.Contains(strings.ToLower(trimmed), "throttle")
			if !hasThrottle && !inAuthGroup {
				findings = append(findings, Finding{
					Severity: MEDIUM,
					File:     filePath,
					Line:     lineNum,
					Recommendation: "API route has no rate limiting. Add 'throttle' middleware to prevent abuse.",
				})
			}
		}
	}

	return findings
}

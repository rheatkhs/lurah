package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Blade unescaped output pattern: {!! $variable !!}
var unescapedBladePattern = regexp.MustCompile(`\{!!\s*(.*?)\s*!!\}`)

// Safe patterns that are acceptable to use unescaped
var safeUnescapedPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\$__env`),           // Blade internal
	regexp.MustCompile(`(?i)csrf_field`),         // CSRF token
	regexp.MustCompile(`(?i)csrf_token`),         // CSRF token
	regexp.MustCompile(`(?i)method_field`),       // Form method spoofing
	regexp.MustCompile(`(?i)app\(\)`),            // App helper
	regexp.MustCompile(`(?i)Js::from`),           // @js directive
	regexp.MustCompile(`(?i)markdown`),           // Markdown rendering
	regexp.MustCompile(`(?i)->render\(\)`),       // Pre-rendered content
}

// ScanXSS walks Blade template files looking for unescaped output ({!! !!}).
func ScanXSS(projectPath string) []Finding {
	var findings []Finding

	viewDirs := []string{
		filepath.Join(projectPath, "resources", "views"),
		filepath.Join(projectPath, "resources", "Views"),
	}

	var viewDir string
	for _, dir := range viewDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			viewDir = dir
			break
		}
	}

	if viewDir == "" {
		return findings
	}

	_ = filepath.Walk(viewDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".blade.php") {
			return nil
		}

		fileFindings := scanBladeForXSS(path)
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings
}

func scanBladeForXSS(filePath string) []Finding {
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

		matches := unescapedBladePattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}

			content := match[1]

			// Skip safe patterns
			isSafe := false
			for _, safe := range safeUnescapedPatterns {
				if safe.MatchString(content) {
					isSafe = true
					break
				}
			}
			if isSafe {
				continue
			}

			findings = append(findings, Finding{
				Severity: HIGH,
				File:     filePath,
				Line:     lineNum,
				Recommendation: fmt.Sprintf(
					"Unescaped Blade output '{!! %s !!}' detected. "+
						"Use {{ }} for escaped output to prevent XSS attacks (SPBE-SI.06).",
					strings.TrimSpace(content)),
			})
		}
	}

	return findings
}

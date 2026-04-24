package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// CustomRule defines a user-specified scanning rule from .lurah.yaml.
type CustomRule struct {
	Name       string `yaml:"name"`
	Pattern    string `yaml:"pattern"`
	TargetDir  string `yaml:"target_dir"`
	Extensions string `yaml:"extensions"`
	Severity   string `yaml:"severity"`
	Message    string `yaml:"message"`
}

// ScanCustomRules runs user-defined regex rules from the config.
func ScanCustomRules(projectPath string, rules []CustomRule) []Finding {
	var findings []Finding

	for _, rule := range rules {
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			findings = append(findings, Finding{
				Severity: MEDIUM,
				File:     filepath.Join(projectPath, ".lurah.yaml"),
				Line:     1,
				Recommendation: fmt.Sprintf(
					"Custom rule '%s' has invalid regex pattern: %s", rule.Name, err.Error()),
			})
			continue
		}

		// Determine target directory
		targetDir := filepath.Join(projectPath, "app")
		if rule.TargetDir != "" {
			targetDir = filepath.Join(projectPath, rule.TargetDir)
		}

		if _, err := os.Stat(targetDir); os.IsNotExist(err) {
			continue
		}

		// Determine file extensions to scan
		extensions := []string{".php"}
		if rule.Extensions != "" {
			extensions = strings.Split(rule.Extensions, ",")
			for i, ext := range extensions {
				ext = strings.TrimSpace(ext)
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				extensions[i] = ext
			}
		}

		// Determine severity
		severity := HIGH
		if rule.Severity != "" {
			switch strings.ToUpper(rule.Severity) {
			case "CRITICAL":
				severity = CRITICAL
			case "HIGH":
				severity = HIGH
			case "MEDIUM":
				severity = MEDIUM
			}
		}

		// Walk and scan files
		_ = filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// Check file extension
			ext := strings.ToLower(filepath.Ext(info.Name()))
			matchExt := false
			for _, e := range extensions {
				if ext == strings.ToLower(e) {
					matchExt = true
					break
				}
			}
			if !matchExt {
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

				if re.MatchString(line) {
					msg := rule.Message
					if msg == "" {
						msg = fmt.Sprintf("Custom rule '%s' matched.", rule.Name)
					}

					findings = append(findings, Finding{
						Severity:       severity,
						File:           path,
						Line:           lineNum,
						Recommendation: msg,
					})
				}
			}

			return nil
		})
	}

	return findings
}

package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// File upload patterns to detect.
var uploadStorePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)->\s*store\s*\(`),
	regexp.MustCompile(`(?i)->\s*storeAs\s*\(`),
	regexp.MustCompile(`(?i)->\s*move\s*\(`),
	regexp.MustCompile(`(?i)->\s*storePublicly\s*\(`),
	regexp.MustCompile(`(?i)->\s*storePubliclyAs\s*\(`),
	regexp.MustCompile(`(?i)Storage\s*::\s*put`),
	regexp.MustCompile(`(?i)Storage\s*::\s*putFile`),
}

// MIME validation patterns — presence of these near uploads indicates validation.
var mimeValidationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)validate\s*\(.*mimes`),
	regexp.MustCompile(`(?i)validate\s*\(.*mimetypes`),
	regexp.MustCompile(`(?i)validate\s*\(.*image`),
	regexp.MustCompile(`(?i)validate\s*\(.*file`),
	regexp.MustCompile(`(?i)'mimes\s*:`),
	regexp.MustCompile(`(?i)'mimetypes\s*:`),
	regexp.MustCompile(`(?i)getMimeType\s*\(`),
	regexp.MustCompile(`(?i)getClientMimeType\s*\(`),
	regexp.MustCompile(`(?i)guessExtension\s*\(`),
}

// ScanFileUpload checks for file upload operations missing MIME type validation.
func ScanFileUpload(projectPath string) []Finding {
	var findings []Finding

	// Scan Controllers and Services
	scanDirs := []string{
		filepath.Join(projectPath, "app", "Http", "Controllers"),
		filepath.Join(projectPath, "app", "http", "controllers"),
		filepath.Join(projectPath, "app", "Services"),
		filepath.Join(projectPath, "app", "services"),
	}

	for _, dir := range scanDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(info.Name()), ".php") {
				return nil
			}

			fileFindings := scanFileForUpload(path)
			findings = append(findings, fileFindings...)
			return nil
		})
	}

	return findings
}

func scanFileForUpload(filePath string) []Finding {
	var findings []Finding

	data, err := os.ReadFile(filePath)
	if err != nil {
		return findings
	}
	content := string(data)

	// Check if file has any upload operations at all
	hasUpload := false
	for _, p := range uploadStorePatterns {
		if p.MatchString(content) {
			hasUpload = true
			break
		}
	}
	if !hasUpload {
		return findings
	}

	// Check if file has MIME validation
	hasMimeValidation := false
	for _, p := range mimeValidationPatterns {
		if p.MatchString(content) {
			hasMimeValidation = true
			break
		}
	}

	// Scan line by line for specific upload locations
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

		for _, p := range uploadStorePatterns {
			if p.MatchString(line) {
				if !hasMimeValidation {
					findings = append(findings, Finding{
						Severity: HIGH,
						File:     filePath,
						Line:     lineNum,
						Recommendation: fmt.Sprintf(
							"File upload without MIME type validation detected. "+
								"Add 'mimes' or 'mimetypes' validation rule to prevent malicious file uploads (SPBE-SI.08)."),
					})
				}

				// Check for public storage without access control
				if strings.Contains(strings.ToLower(line), "public") {
					findings = append(findings, Finding{
						Severity: MEDIUM,
						File:     filePath,
						Line:     lineNum,
						Recommendation: "File stored to public disk. Ensure sensitive files are stored on a private disk " +
							"with proper access control.",
					})
				}

				break // one finding per line
			}
		}
	}

	return findings
}

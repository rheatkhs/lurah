package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// fillablePattern matches $fillable property declaration.
var fillablePattern = regexp.MustCompile(`(?i)protected\s+\$fillable\s*=`)

// guardedPattern matches $guarded property declaration.
var guardedPattern = regexp.MustCompile(`(?i)protected\s+\$guarded\s*=`)

// guardedEmptyPattern matches $guarded = [] (allowing all mass assignment).
var guardedEmptyPattern = regexp.MustCompile(`(?i)protected\s+\$guarded\s*=\s*\[\s*\]`)

// extendsModelPattern matches class declarations that extend Model.
var extendsModelPattern = regexp.MustCompile(`(?i)class\s+\w+\s+extends\s+.*Model`)

// ScanMassAssignment walks Eloquent models to check for missing $fillable/$guarded.
func ScanMassAssignment(projectPath string) []Finding {
	var findings []Finding

	modelDirs := []string{
		filepath.Join(projectPath, "app", "Models"),
		filepath.Join(projectPath, "app", "models"),
		filepath.Join(projectPath, "app"), // Older Laravel structure
	}

	for _, dir := range modelDirs {
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

			// Skip non-model directories when scanning app/ root
			if dir == filepath.Join(projectPath, "app") {
				rel, _ := filepath.Rel(dir, path)
				if strings.Contains(rel, string(filepath.Separator)) {
					// Skip subdirectories — only check root app/*.php
					return nil
				}
			}

			fileFindings := scanModelFile(path)
			findings = append(findings, fileFindings...)
			return nil
		})
	}

	return findings
}

func scanModelFile(filePath string) []Finding {
	var findings []Finding

	data, err := os.ReadFile(filePath)
	if err != nil {
		return findings
	}
	content := string(data)

	// Check if this file is an Eloquent model
	if !extendsModelPattern.MatchString(content) {
		return findings
	}

	hasFillable := fillablePattern.MatchString(content)
	hasGuarded := guardedPattern.MatchString(content)
	hasEmptyGuarded := guardedEmptyPattern.MatchString(content)

	// Find the class declaration line for reporting
	classLine := 1
	file, err := os.Open(filePath)
	if err == nil {
		sc := bufio.NewScanner(file)
		ln := 0
		for sc.Scan() {
			ln++
			if extendsModelPattern.MatchString(sc.Text()) {
				classLine = ln
				break
			}
		}
		file.Close()
	}

	if !hasFillable && !hasGuarded {
		findings = append(findings, Finding{
			Severity: HIGH,
			File:     filePath,
			Line:     classLine,
			Recommendation: "Eloquent model has no $fillable or $guarded property. " +
				"This allows mass assignment of all attributes. Define $fillable to whitelist assignable fields (SPBE-SI.07).",
		})
	} else if hasEmptyGuarded {
		findings = append(findings, Finding{
			Severity: HIGH,
			File:     filePath,
			Line:     classLine,
			Recommendation: "Model has $guarded = [] which disables mass assignment protection entirely. " +
				"Use $fillable to explicitly whitelist fields instead (SPBE-SI.07).",
		})
	}

	return findings
}

package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FixableRules defines which findings can be auto-fixed and how.
type FixAction struct {
	Description string
	Apply       func(projectPath string, finding Finding) error
}

// ApplyFixes attempts to auto-fix findings that have known fixes.
// Returns the count of fixes applied.
func ApplyFixes(projectPath string, findings []Finding) (int, []string) {
	fixed := 0
	var messages []string

	for _, f := range findings {
		if msg, ok := tryFix(projectPath, f); ok {
			fixed++
			messages = append(messages, msg)
		}
	}

	return fixed, messages
}

func tryFix(projectPath string, f Finding) (string, bool) {
	// Fix APP_DEBUG=true → APP_DEBUG=false
	if f.Severity == CRITICAL &&
		strings.Contains(f.Recommendation, "APP_DEBUG is true") {
		envPath := filepath.Join(projectPath, ".env")
		if err := replaceEnvValue(envPath, "APP_DEBUG", "false"); err == nil {
			return fmt.Sprintf("Fixed: Set APP_DEBUG=false in %s", envPath), true
		}
	}

	return "", false
}

// replaceEnvValue replaces a key's value in a .env file.
func replaceEnvValue(envPath, key, newValue string) error {
	file, err := os.Open(envPath)
	if err != nil {
		return err
	}

	var lines []string
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		if !strings.HasPrefix(trimmed, "#") && strings.Contains(trimmed, "=") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[0]) == key {
				line = key + "=" + newValue
			}
		}
		lines = append(lines, line)
	}
	file.Close()

	return os.WriteFile(envPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

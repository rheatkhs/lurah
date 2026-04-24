package scanner

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LurahConfig represents the .lurah.yaml configuration file.
type LurahConfig struct {
	Version      string   `yaml:"version"`
	ExcludePaths []string `yaml:"exclude_paths"`
	MinSeverity  string   `yaml:"min_severity"`
	Scanners     struct {
		Secret         bool `yaml:"secret"`
		PII            bool `yaml:"pii"`
		SQLi           bool `yaml:"sqli"`
		CSRF           bool `yaml:"csrf"`
		Middleware     bool `yaml:"middleware"`
		Dependency     bool `yaml:"dependency"`
		Config         bool `yaml:"config"`
		EnvDiff        bool `yaml:"env_diff"`
		XSS            bool `yaml:"xss"`
		MassAssignment bool `yaml:"mass_assignment"`
		FileUpload     bool `yaml:"file_upload"`
		Auth           bool `yaml:"auth"`
		Advisory       bool `yaml:"advisory"`
	} `yaml:"scanners"`
	PII struct {
		CustomPatterns []string `yaml:"custom_patterns"`
	} `yaml:"pii"`
	CustomRules []CustomRule `yaml:"custom_rules"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() LurahConfig {
	cfg := LurahConfig{
		Version:      "1.0",
		ExcludePaths: []string{"vendor", "node_modules", "storage", ".git"},
		MinSeverity:  "MEDIUM",
	}
	cfg.Scanners.Secret = true
	cfg.Scanners.PII = true
	cfg.Scanners.SQLi = true
	cfg.Scanners.CSRF = true
	cfg.Scanners.Middleware = true
	cfg.Scanners.Dependency = true
	cfg.Scanners.Config = true
	cfg.Scanners.EnvDiff = true
	cfg.Scanners.XSS = true
	cfg.Scanners.MassAssignment = true
	cfg.Scanners.FileUpload = true
	cfg.Scanners.Auth = true
	cfg.Scanners.Advisory = true
	return cfg
}

// WriteConfig writes a LurahConfig to a .lurah.yaml file.
func WriteConfig(projectPath string, cfg LurahConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	header := []byte("# Lurah Configuration\n# https://github.com/rheatkhs/lurah\n\n")
	content := append(header, data...)

	return os.WriteFile(filepath.Join(projectPath, ".lurah.yaml"), content, 0644)
}

// LoadConfig loads a .lurah.yaml from the project path.
// Returns default config if the file doesn't exist.
func LoadConfig(projectPath string) LurahConfig {
	cfg := DefaultConfig()

	data, err := os.ReadFile(filepath.Join(projectPath, ".lurah.yaml"))
	if err != nil {
		return cfg
	}

	_ = yaml.Unmarshal(data, &cfg)
	return cfg
}

// FilterBySeverity filters findings to only include those at or above the minimum severity.
func FilterBySeverity(findings []Finding, minSeverity string) []Finding {
	severityOrder := map[Severity]int{
		MEDIUM:   1,
		HIGH:     2,
		CRITICAL: 3,
	}

	minLevel, ok := severityOrder[Severity(minSeverity)]
	if !ok {
		return findings
	}

	var filtered []Finding
	for _, f := range findings {
		if severityOrder[f.Severity] >= minLevel {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

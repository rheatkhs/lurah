package scanner

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// BaselineEntry represents a single suppressed finding.
type BaselineEntry struct {
	Hash           string `json:"hash"`
	Severity       string `json:"severity"`
	File           string `json:"file"`
	Recommendation string `json:"recommendation"`
}

// Baseline represents the .lurah-baseline.json file.
type Baseline struct {
	Version string          `json:"version"`
	Entries []BaselineEntry `json:"entries"`
}

// findingHash generates a unique hash for a finding (ignoring line numbers which may shift).
func findingHash(f Finding) string {
	data := fmt.Sprintf("%s|%s|%s", f.Severity, filepath.Base(f.File), f.Recommendation)
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h[:8])
}

// LoadBaseline reads the .lurah-baseline.json file.
func LoadBaseline(projectPath string) (*Baseline, error) {
	baselinePath := filepath.Join(projectPath, ".lurah-baseline.json")
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, err
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, err
	}

	return &baseline, nil
}

// SaveBaseline writes the current findings as a baseline file.
func SaveBaseline(projectPath string, findings []Finding) error {
	entries := make([]BaselineEntry, 0, len(findings))
	for _, f := range findings {
		entries = append(entries, BaselineEntry{
			Hash:           findingHash(f),
			Severity:       string(f.Severity),
			File:           f.File,
			Recommendation: f.Recommendation,
		})
	}

	// Sort for deterministic output
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Hash < entries[j].Hash
	})

	baseline := Baseline{
		Version: "1.0",
		Entries: entries,
	}

	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(projectPath, ".lurah-baseline.json"), data, 0644)
}

// ApplyBaseline filters out findings that exist in the baseline, returning only new issues.
func ApplyBaseline(findings []Finding, baseline *Baseline) []Finding {
	if baseline == nil {
		return findings
	}

	// Build lookup set from baseline
	suppressed := make(map[string]bool, len(baseline.Entries))
	for _, entry := range baseline.Entries {
		suppressed[entry.Hash] = true
	}

	var newFindings []Finding
	for _, f := range findings {
		if !suppressed[findingHash(f)] {
			newFindings = append(newFindings, f)
		}
	}

	return newFindings
}

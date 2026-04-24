package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/rheatkhs/lurah/scanner"
)

// JSONReport is the structure for JSON output format.
type JSONReport struct {
	Tool      string       `json:"tool"`
	Version   string       `json:"version"`
	Timestamp string       `json:"timestamp"`
	Project   string       `json:"project"`
	Summary   JSONSummary  `json:"summary"`
	Findings  []JSONResult `json:"findings"`
}

// JSONSummary holds the count of findings by severity.
type JSONSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
}

// JSONResult represents a single finding in JSON format.
type JSONResult struct {
	Severity       string `json:"severity"`
	File           string `json:"file"`
	Line           int    `json:"line"`
	Recommendation string `json:"recommendation"`
}

// PrintJSON outputs findings as a structured JSON document.
func PrintJSON(findings []scanner.Finding, projectPath string) {
	summary := JSONSummary{Total: len(findings)}

	results := make([]JSONResult, 0, len(findings))
	for _, f := range findings {
		switch f.Severity {
		case scanner.CRITICAL:
			summary.Critical++
		case scanner.HIGH:
			summary.High++
		case scanner.MEDIUM:
			summary.Medium++
		}

		results = append(results, JSONResult{
			Severity:       string(f.Severity),
			File:           f.File,
			Line:           f.Line,
			Recommendation: f.Recommendation,
		})
	}

	report := JSONReport{
		Tool:      "lurah",
		Version:   "1.0.0",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Project:   projectPath,
		Summary:   summary,
		Findings:  results,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
	}
}

// SARIFReport is the top-level SARIF v2.1.0 structure for GitHub Code Scanning integration.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifact `json:"artifactLocation"`
	Region           SARIFRegion   `json:"region"`
}

type SARIFArtifact struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

// PrintSARIF outputs findings in SARIF v2.1.0 format.
func PrintSARIF(findings []scanner.Finding) {
	results := make([]SARIFResult, 0, len(findings))

	for _, f := range findings {
		level := "warning"
		ruleID := "security/unknown"

		switch f.Severity {
		case scanner.CRITICAL:
			level = "error"
			ruleID = "security/critical"
		case scanner.HIGH:
			level = "warning"
			ruleID = "security/high"
		case scanner.MEDIUM:
			level = "note"
			ruleID = "security/medium"
		}

		results = append(results, SARIFResult{
			RuleID: ruleID,
			Level:  level,
			Message: SARIFMessage{
				Text: f.Recommendation,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifact{URI: f.File},
						Region:           SARIFRegion{StartLine: f.Line},
					},
				},
			},
		})
	}

	report := SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:    "lurah",
						Version: "1.0.0",
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding SARIF: %v\n", err)
	}
}

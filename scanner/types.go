package scanner

// Severity represents the severity level of a security finding.
type Severity string

const (
	CRITICAL Severity = "CRITICAL"
	HIGH     Severity = "HIGH"
	MEDIUM   Severity = "MEDIUM"
)

// Finding represents a single security issue discovered during a scan.
type Finding struct {
	Severity       Severity `json:"severity"`
	File           string   `json:"file"`
	Line           int      `json:"line"`
	Recommendation string   `json:"recommendation"`
}

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
	Severity       Severity
	File           string
	Line           int
	Recommendation string
}

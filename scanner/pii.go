package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// piiPatterns are PII variable names that must be masked before API output.
var piiPatterns = []string{
	// Indonesian identity
	"nik",          // Nomor Induk Kependudukan
	"nip",          // Nomor Induk Pegawai
	"npwp",         // Nomor Pokok Wajib Pajak
	"no_ktp",       // Nomor KTP
	"no_kk",        // Nomor Kartu Keluarga
	"no_sim",       // Nomor SIM
	"no_passport",  // Nomor Paspor
	"no_bpjs",      // Nomor BPJS

	// Financial
	"rekening",     // Nomor Rekening Bank
	"no_rekening",  // Nomor Rekening (alt)
	"no_rek",       // Nomor Rekening (short)
	"kartu_kredit", // Nomor Kartu Kredit
	"credit_card",  // Credit card number
	"card_number",  // Card number

	// Contact / personal
	"no_hp",        // Nomor Handphone
	"no_telp",      // Nomor Telepon
	"phone_number", // Phone number
	"alamat",       // Alamat (address)
	"email",        // Email address
	"tanggal_lahir", // Tanggal Lahir (date of birth)
	"tempat_lahir", // Tempat Lahir (place of birth)
	"nama_ibu",     // Nama Ibu Kandung (mother's maiden name)

	// Biometric / sensitive
	"sidik_jari",   // Sidik Jari (fingerprint)
	"foto_ktp",     // Foto KTP
	"password",     // Password
	"pin",          // PIN
}

// jsonResponsePattern matches common Laravel JSON response patterns.
var jsonResponsePattern = regexp.MustCompile(`(?i)(response\(\)\s*->\s*json|return\s+.*json|->toArray|Resource::collection|JsonResponse)`)

// piiVarRegex builds a regex to match PHP variable usage like $nik, $npwp, $rekening.
func piiVarRegex(name string) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`(?i)\$%s\b`, regexp.QuoteMeta(name)))
}

// functionStartPattern detects PHP function declarations.
var functionStartPattern = regexp.MustCompile(`(?i)(public|protected|private)?\s*function\s+\w+`)

// ScanPII walks the Controllers directory looking for PII variables
// returned in raw JSON responses. Uses multi-line function-scope analysis.
func ScanPII(projectPath string) []Finding {
	var findings []Finding

	// Laravel controller paths (handle both lowercase and Pascal case)
	controllerDirs := []string{
		filepath.Join(projectPath, "app", "Http", "Controllers"),
		filepath.Join(projectPath, "app", "http", "controllers"),
	}

	var controllerDir string
	for _, dir := range controllerDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			controllerDir = dir
			break
		}
	}

	if controllerDir == "" {
		return findings
	}

	// Walk all .php files recursively
	_ = filepath.Walk(controllerDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".php") {
			return nil
		}

		fileFindings := scanPHPFileMultiLine(path)
		findings = append(findings, fileFindings...)
		return nil
	})

	return findings
}

// piiOccurrence tracks where a PII variable appears in a function.
type piiOccurrence struct {
	varName string
	line    int
}

// scanPHPFileMultiLine performs function-scope PII detection.
// It tracks PII variables across an entire function body and checks if
// the function contains a JSON response anywhere (not just on the same line).
func scanPHPFileMultiLine(filePath string) []Finding {
	var findings []Finding

	file, err := os.Open(filePath)
	if err != nil {
		return findings
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	lineNum := 0

	// Per-function tracking
	var funcPIIVars []piiOccurrence
	var funcHasJSON bool
	var funcJSONLine int
	inFunction := false
	braceDepth := 0
	funcStartLine := 0

	for sc.Scan() {
		lineNum++
		line := sc.Text()

		// Detect function boundaries
		if functionStartPattern.MatchString(line) {
			// Flush previous function findings
			if inFunction {
				findings = append(findings, emitFunctionFindings(filePath, funcPIIVars, funcHasJSON, funcJSONLine)...)
			}

			inFunction = true
			funcPIIVars = nil
			funcHasJSON = false
			funcJSONLine = 0
			funcStartLine = lineNum
			braceDepth = 0
		}

		if inFunction {
			braceDepth += strings.Count(line, "{")
			braceDepth -= strings.Count(line, "}")

			// Track PII variable occurrences
			for _, pii := range piiPatterns {
				re := piiVarRegex(pii)
				if re.MatchString(line) {
					funcPIIVars = append(funcPIIVars, piiOccurrence{
						varName: pii,
						line:    lineNum,
					})
				}
			}

			// Track JSON response presence
			if jsonResponsePattern.MatchString(line) {
				funcHasJSON = true
				if funcJSONLine == 0 {
					funcJSONLine = lineNum
				}
			}

			// End of function
			if braceDepth <= 0 && lineNum > funcStartLine {
				findings = append(findings, emitFunctionFindings(filePath, funcPIIVars, funcHasJSON, funcJSONLine)...)
				inFunction = false
				funcPIIVars = nil
				funcHasJSON = false
			}
		}
	}

	// Handle last function in file
	if inFunction && len(funcPIIVars) > 0 {
		findings = append(findings, emitFunctionFindings(filePath, funcPIIVars, funcHasJSON, funcJSONLine)...)
	}

	return findings
}

// emitFunctionFindings generates findings for PII variables in a function scope.
func emitFunctionFindings(filePath string, piiVars []piiOccurrence, hasJSON bool, jsonLine int) []Finding {
	var findings []Finding

	// Deduplicate by variable name — only flag once per variable per function
	seen := make(map[string]piiOccurrence)
	for _, pv := range piiVars {
		if _, ok := seen[pv.varName]; !ok {
			seen[pv.varName] = pv
		}
	}

	for _, pv := range seen {
		if hasJSON {
			findings = append(findings, Finding{
				Severity: HIGH,
				File:     filePath,
				Line:     pv.line,
				Recommendation: fmt.Sprintf(
					"PII variable '$%s' found in function that returns JSON (line %d). "+
						"Apply data masking before output (SPBE-PD.01).", pv.varName, jsonLine),
			})
		} else {
			findings = append(findings, Finding{
				Severity: MEDIUM,
				File:     filePath,
				Line:     pv.line,
				Recommendation: fmt.Sprintf(
					"PII variable '$%s' detected. "+
						"Ensure it is masked before any API response (SPBE-PD.01).", pv.varName),
			})
		}
	}

	return findings
}

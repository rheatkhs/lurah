package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PackagistAdvisory represents a single security advisory from Packagist.
type PackagistAdvisory struct {
	AdvisoryID  string `json:"advisoryId"`
	PackageName string `json:"packageName"`
	Title       string `json:"title"`
	Link        string `json:"link"`
	CVE         string `json:"cve"`
	AffectedVersions string `json:"affectedVersions"`
	Sources     []struct {
		Name      string `json:"name"`
		RemoteID  string `json:"remoteId"`
	} `json:"sources"`
}

// ScanAdvisories checks installed packages against Packagist security advisories.
func ScanAdvisories(projectPath string) []Finding {
	var findings []Finding

	lockPath := filepath.Join(projectPath, "composer.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		return findings
	}

	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return findings
	}

	// Build package list for API query
	packages := make(map[string]string)
	for _, pkg := range lock.Packages {
		packages[pkg.Name] = pkg.Version
	}
	for _, pkg := range lock.PackagesDev {
		packages[pkg.Name] = pkg.Version
	}

	if len(packages) == 0 {
		return findings
	}

	// Query Packagist Security Advisories API
	advisories, err := fetchAdvisories(packages)
	if err != nil {
		// Offline fallback — skip advisory check silently
		return findings
	}

	for pkgName, advList := range advisories {
		version := packages[pkgName]
		for _, adv := range advList {
			cveInfo := ""
			if adv.CVE != "" {
				cveInfo = fmt.Sprintf(" (%s)", adv.CVE)
			}

			findings = append(findings, Finding{
				Severity: CRITICAL,
				File:     lockPath,
				Line:     1,
				Recommendation: fmt.Sprintf(
					"Vulnerable package '%s' v%s: %s%s. Affected versions: %s. See: %s",
					pkgName, version, adv.Title, cveInfo, adv.AffectedVersions, adv.Link),
			})
		}
	}

	return findings
}

// fetchAdvisories queries the Packagist Security Advisories API.
func fetchAdvisories(packages map[string]string) (map[string][]PackagistAdvisory, error) {
	// Build query body: {"packages": {"vendor/package": "1.0.0", ...}}
	body := struct {
		Packages map[string]string `json:"packages"`
	}{
		Packages: packages,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(
		"https://packagist.org/api/security-advisories",
		"application/json",
		strings.NewReader(string(jsonBody)),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("packagist API returned %d", resp.StatusCode)
	}

	var result struct {
		Advisories map[string][]PackagistAdvisory `json:"advisories"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Advisories, nil
}

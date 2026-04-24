package web

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	"github.com/rheatkhs/lurah/scanner"
)

//go:embed index.html
var indexHTML []byte

// Server represents the web dashboard server.
type Server struct {
	Port int
}

// NewServer creates a new dashboard server.
func NewServer(port int) *Server {
	return &Server{Port: port}
}

// Start launches the HTTP server and opens the browser.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Root dashboard handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write(indexHTML)
	})

	// API Endpoints
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/select-folder", s.handleSelectFolder)

	addr := fmt.Sprintf("localhost:%d", s.Port)
	fmt.Printf("  [+] Dashboard starting at http://%s\n", addr)
	fmt.Println("  [+] Press Ctrl+C to stop the server")

	// Auto-open browser
	go func() {
		_ = OpenBrowser("http://" + addr)
	}()

	return http.ListenAndServe(addr, mux)
}

// ScanRequest represents a request to scan a path.
type ScanRequest struct {
	Path string `json:"path"`
}

// ScanResponse represents the response containing findings.
type ScanResponse struct {
	Findings []scanner.Finding `json:"findings"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var req ScanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Trigger all scanners
	findings := []scanner.Finding{}
	findings = append(findings, scanner.ScanSecrets(req.Path)...)
	findings = append(findings, scanner.ScanPII(req.Path)...)
	findings = append(findings, scanner.ScanSQLInjection(req.Path)...)
	findings = append(findings, scanner.ScanCSRF(req.Path)...)
	findings = append(findings, scanner.ScanMiddleware(req.Path)...)
	findings = append(findings, scanner.ScanDependencies(req.Path)...)
	findings = append(findings, scanner.ScanConfig(req.Path)...)
	findings = append(findings, scanner.ScanEnvDiff(req.Path)...)
	findings = append(findings, scanner.ScanXSS(req.Path)...)
	findings = append(findings, scanner.ScanMassAssignment(req.Path)...)
	findings = append(findings, scanner.ScanFileUpload(req.Path)...)
	findings = append(findings, scanner.ScanAuth(req.Path)...)
	findings = append(findings, scanner.ScanAdvisories(req.Path)...)

	resp := ScanResponse{Findings: findings}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleSelectFolder(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "windows" {
		http.Error(w, "Native folder picker only supported on Windows", http.StatusNotImplemented)
		return
	}

	// PowerShell command to open folder dialog
	psCmd := "Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.FolderBrowserDialog; if($f.ShowDialog() -eq 'OK') { $f.SelectedPath }"
	out, err := exec.Command("powershell", "-NoProfile", "-Command", psCmd).Output()
	if err != nil {
		http.Error(w, "Failed to open folder dialog", http.StatusInternalServerError)
		return
	}

	path := strings.TrimSpace(string(out))
	if path == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"path": path})
}

// OpenBrowser opens the specified URL in the default browser of the user.
func OpenBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd = "open"
		args = []string{url}
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
		args = []string{url}
	}
	return exec.Command(cmd, args...).Start()
}

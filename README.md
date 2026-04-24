# Lurah

**Laravel Security Auditor for SPBE Compliance**

Lurah is a cross-platform CLI tool written in Go that performs static security analysis on Laravel projects. It targets compliance with Indonesian government SPBE (*Sistem Pemerintahan Berbasis Elektronik*) standards, identifying misconfigurations, PII exposure, SQL injection risks, and more.

```
  ██╗     ██╗   ██╗██████╗  █████╗ ██╗  ██╗
  ██║     ██║   ██║██╔══██╗██╔══██╗██║  ██║
  ██║     ██║   ██║██████╔╝███████║███████║
  ██║     ██║   ██║██╔══██╗██╔══██║██╔══██║
  ███████╗╚██████╔╝██║  ██║██║  ██║██║  ██║
  ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
```

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Scanners](#scanners)
- [Configuration](#configuration)
- [Output Formats](#output-formats)
- [CI/CD Integration](#cicd-integration)
- [Project Structure](#project-structure)
- [SPBE Standard References](#spbe-standard-references)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **8 built-in security scanners** covering secrets, PII, SQL injection, CSRF, middleware, dependencies, config, and environment drift
- **Multi-line function-scope analysis** — PII detection tracks variables across entire function bodies, not just single lines
- **Auto-fix mode** — automatically patch simple issues like `APP_DEBUG=true`
- **Watch mode** — re-scan on file changes during development
- **Multiple output formats** — table (colored), JSON, and SARIF for CI/CD integration
- **Configurable** — `.lurah.yaml` to enable/disable scanners, set severity thresholds, and exclude paths
- **Cross-platform** — Windows and Linux compatible via `filepath.Join`
- **CI/CD friendly** — exits with code 1 on critical findings

---

## Installation

### Prerequisites

- [Go 1.21+](https://go.dev/dl/)

### Build from source

```bash
git clone https://github.com/rheatkhs/lurah.git
cd lurah
go build -o lurah.exe .    # Windows
go build -o lurah .         # Linux/macOS
```

---

## Usage

### Quick scan

```bash
# Scan the current directory
lurah scan

# Scan a specific project
lurah scan --path /var/www/my-app

# Windows
lurah.exe scan --path C:\laragon\www\my-project
```

### Filter by severity

```bash
# Only show HIGH and CRITICAL findings
lurah scan --min-severity HIGH
```

### Auto-fix

```bash
# Automatically fix simple issues (e.g., set APP_DEBUG=false)
lurah scan --fix
```

### Output formats

```bash
# JSON output for programmatic consumption
lurah scan --format json

# SARIF output for GitHub Code Scanning
lurah scan --format sarif > results.sarif
```

### Watch mode

```bash
# Re-scan automatically when files change
lurah watch --path ./
```

### Initialize configuration

```bash
# Generate a .lurah.yaml with defaults
lurah init
```

### Example output

```
  Scanning: C:\laragon\www\my-project

  [1/8] Running Secret Scanner...
  [2/8] Running PII Scanner...
  [3/8] Running SQL Injection Scanner...
  [4/8] Running CSRF Scanner...
  [5/8] Running Middleware Scanner...
  [6/8] Running Dependency Scanner...
  [7/8] Running Config Scanner...
  [8/8] Running Env Diff Scanner...

  Found 14 issue(s):

  ┌──────────┬──────────────────────────────┬────────────────────────────────────────────────┐
  │ Severity │ File                         │ Recommendation                                 │
  ├──────────┼──────────────────────────────┼────────────────────────────────────────────────┤
  │ CRITICAL │ .env:4                       │ APP_DEBUG is true in a non-local environment.   │
  │          │                              │ Disable debug mode for production (SPBE-SI.03). │
  ├──────────┼──────────────────────────────┼────────────────────────────────────────────────┤
  │ CRITICAL │ .env:3                       │ APP_KEY is empty. Run 'php artisan              │
  │          │                              │ key:generate' (SPBE-SI.02).                     │
  ├──────────┼──────────────────────────────┼────────────────────────────────────────────────┤
  │ HIGH     │ WargaController.php:4        │ PII variable '$nik' found in function that      │
  │          │                              │ returns JSON. Apply masking (SPBE-PD.01).        │
  ├──────────┼──────────────────────────────┼────────────────────────────────────────────────┤
  │ CRITICAL │ Report.php:4                 │ Potential SQL injection: raw query with          │
  │          │                              │ variable interpolation (SPBE-SI.04).             │
  └──────────┴──────────────────────────────┴────────────────────────────────────────────────┘

  Summary: 14 findings (3 critical, 7 high, 4 medium)
```

---

## Scanners

| Scanner | What it detects | Severity |
|---|---|---|
| **Secret** | `APP_DEBUG=true` in non-local env, empty `APP_KEY` | CRITICAL |
| **PII** | `$nik`, `$npwp`, `$rekening` in Controllers — elevated if returned in JSON | HIGH / MEDIUM |
| **SQL Injection** | `DB::raw()`, `whereRaw()`, `selectRaw()` with variable interpolation | CRITICAL |
| **CSRF** | Wildcard or excessive `$except` entries in `VerifyCsrfToken` | HIGH / MEDIUM |
| **Middleware** | Sensitive routes (`/admin`, `/payment`, `/api/*`) without `auth` or `throttle` | HIGH / MEDIUM |
| **Dependency** | Debug packages in production deps, outdated PHP requirements | HIGH / MEDIUM |
| **Config** | Hardcoded `debug => true`, cleartext `password`/`secret`/`api_key` in config/ | HIGH |
| **Env Diff** | Keys in `.env.example` missing from `.env`, placeholder values | MEDIUM |

---

## Configuration

Run `lurah init` to generate a `.lurah.yaml`:

```yaml
# Lurah Configuration
version: "1.0"
exclude_paths:
  - vendor
  - node_modules
  - storage
  - .git
min_severity: MEDIUM
scanners:
  secret: true
  pii: true
  sqli: true
  csrf: true
  middleware: true
  dependency: true
  config: true
  env_diff: true
pii:
  custom_patterns: []
```

| Key | Description |
|---|---|
| `exclude_paths` | Directories to skip during scanning |
| `min_severity` | Minimum severity threshold: `MEDIUM`, `HIGH`, or `CRITICAL` |
| `scanners.*` | Toggle individual scanners on/off |
| `pii.custom_patterns` | Additional PII variable names to detect |

---

## Output Formats

| Format | Flag | Use Case |
|---|---|---|
| **Table** | `--format table` (default) | Human-readable terminal output with color-coded severity |
| **JSON** | `--format json` | Structured output for scripts and dashboards |
| **SARIF** | `--format sarif` | GitHub Code Scanning, SonarQube, and other SARIF-compatible tools |

### JSON schema

```json
{
  "tool": "lurah",
  "version": "1.1.0",
  "timestamp": "2026-04-24T01:55:00Z",
  "project": "/path/to/project",
  "summary": {
    "total": 14,
    "critical": 3,
    "high": 7,
    "medium": 4
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "file": ".env",
      "line": 4,
      "recommendation": "..."
    }
  ]
}
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]
jobs:
  lurah:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - run: go install github.com/rheatkhs/lurah@latest
      - run: lurah scan --format sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No critical findings |
| `1` | One or more CRITICAL findings detected |

---

## Project Structure

```
lurah/
├── main.go                        # Entry point
├── cmd/
│   ├── root.go                    # Root command, banner, --path flag
│   ├── scan.go                    # Scan + watch commands, --format/--fix/--min-severity flags
│   └── init.go                    # Init command (.lurah.yaml generation)
├── scanner/
│   ├── types.go                   # Finding struct, Severity constants
│   ├── secret.go                  # .env secret scanner
│   ├── pii.go                     # PII scanner (multi-line function-scope)
│   ├── sqli.go                    # SQL injection pattern scanner
│   ├── csrf.go                    # CSRF exclusion scanner
│   ├── middleware.go              # Route middleware auditor
│   ├── dependency.go              # Composer.lock + .env diff scanner
│   ├── config.go                  # Config file scanner
│   ├── fix.go                     # Auto-fix logic
│   ├── lurah_config.go            # .lurah.yaml config loader
│   ├── secret_test.go             # Unit tests
│   ├── pii_test.go
│   ├── sqli_test.go
│   └── csrf_test.go
└── reporter/
    ├── table.go                   # Colored terminal table
    └── json.go                    # JSON + SARIF formatters
```

---

## SPBE Standard References

| Code | Standard | Description |
|---|---|---|
| SPBE-SI.01 | Otentikasi Pengguna | Authentication required on sensitive endpoints |
| SPBE-SI.02 | Keamanan Kunci Enkripsi | Encryption key management (APP_KEY) |
| SPBE-SI.03 | Perlindungan Informasi Sensitif | Debug mode and secret exposure prevention |
| SPBE-SI.04 | Pencegahan Injeksi | SQL injection and input validation |
| SPBE-SI.05 | Perlindungan CSRF | Cross-site request forgery protection |
| SPBE-PD.01 | Perlindungan Data Pribadi | Personal data (PII) masking and protection |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-scanner`)
3. Write tests for your changes
4. Ensure all tests pass (`go test ./...`)
5. Submit a Pull Request

### Adding a scanner

1. Create `scanner/your_scanner.go` implementing a function `ScanYour(projectPath string) []Finding`
2. Add a toggle in `LurahConfig.Scanners`
3. Wire it into `cmd/scan.go`
4. Write tests in `scanner/your_scanner_test.go`

---

## License

MIT License -- see [LICENSE](LICENSE) for details.

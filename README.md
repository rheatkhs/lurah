# 🏘️ Lurah

**Laravel Security Auditor for SPBE Compliance**

Lurah is a cross-platform CLI tool written in Go that audits Laravel projects for security vulnerabilities, focusing on Indonesian government (SPBE) standards.

```
  ██╗     ██╗   ██╗██████╗  █████╗ ██╗  ██╗
  ██║     ██║   ██║██╔══██╗██╔══██╗██║  ██║
  ██║     ██║   ██║██████╔╝███████║███████║
  ██║     ██║   ██║██╔══██╗██╔══██║██╔══██║
  ███████╗╚██████╔╝██║  ██║██║  ██║██║  ██║
  ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
```

---

## Features

| Scanner | What it checks | Severity |
|---|---|---|
| **Secret Scanner** | `APP_DEBUG=true` in non-local environments | 🔴 CRITICAL |
| **Secret Scanner** | Empty `APP_KEY` (missing encryption key) | 🔴 CRITICAL |
| **PII Scanner** | `$nik`, `$npwp`, `$rekening` returned in raw JSON responses | 🟡 HIGH |
| **PII Scanner** | PII variables detected in Controllers (general usage) | 🔵 MEDIUM |

### Key Highlights

- 🎯 **SPBE-aligned** — References SPBE-SI.02, SPBE-SI.03, and SPBE-PD.01 standards
- 🖥️ **Cross-platform** — Windows & Linux compatible (uses `filepath.Join` throughout)
- 🎨 **Colored output** — Severity-coded table in your terminal
- 🔄 **CI/CD friendly** — Exits with code `1` on CRITICAL findings, `0` otherwise
- ⚡ **Zero config** — Point it at a Laravel project and go

---

## Installation

### Prerequisites

- [Go 1.21+](https://go.dev/dl/)

### Build from source

```bash
git clone https://github.com/rheatkhs/lurah.git
cd lurah
go build -o lurah.exe .
```

---

## Usage

```bash
# Scan the current directory
lurah scan

# Scan a specific Laravel project
lurah scan --path /var/www/my-laravel-app

# Windows example
lurah.exe scan --path C:\laragon\www\my-project

# Show help
lurah --help
lurah scan --help
```

### Example Output

```
  Scanning: C:\laragon\www\my-project

  [1/2] Running Secret Scanner...
  [2/2] Running PII Scanner...

  Found 3 issue(s):

┌──────────┬─────────────────────────────┬──────────────────────────────────────────────────────┐
│ Severity │ File                        │ Recommendation                                       │
├──────────┼─────────────────────────────┼──────────────────────────────────────────────────────┤
│ CRITICAL │ .env:4                      │ APP_DEBUG is true in a non-local environment.         │
│          │                             │ Disable debug mode for production/staging (SPBE-SI.03)│
├──────────┼─────────────────────────────┼──────────────────────────────────────────────────────┤
│ HIGH     │ WargaController.php:14      │ PII variable '$nik' returned in raw JSON response.   │
│          │                             │ Apply data masking before output (SPBE-PD.01).        │
├──────────┼─────────────────────────────┼──────────────────────────────────────────────────────┤
│ MEDIUM   │ WargaController.php:9       │ PII variable '$nik' detected. Ensure it is masked    │
│          │                             │ before any API response (SPBE-PD.01).                 │
└──────────┴─────────────────────────────┴──────────────────────────────────────────────────────┘

  Summary: 3 findings (1 critical, 1 high, 1 medium)
```

---

## Project Structure

```
lurah/
├── main.go                 # Entry point
├── cmd/
│   ├── root.go             # Root Cobra command + ASCII banner
│   └── scan.go             # "scan" subcommand orchestrator
├── scanner/
│   ├── types.go            # Finding struct + Severity constants
│   ├── secret.go           # .env secret scanner
│   └── pii.go              # PII variable scanner for Controllers
└── reporter/
    └── table.go            # Colored terminal table output
```

---

## SPBE Standard References

| Code | Standard | What Lurah Checks |
|---|---|---|
| **SPBE-SI.02** | Keamanan Kunci Enkripsi | Empty `APP_KEY` in `.env` |
| **SPBE-SI.03** | Perlindungan Informasi Sensitif | `APP_DEBUG=true` in production |
| **SPBE-PD.01** | Perlindungan Data Pribadi | PII variables (`nik`, `npwp`, `rekening`) exposed in API responses |

---

## Dependencies

| Package | Purpose |
|---|---|
| [spf13/cobra](https://github.com/spf13/cobra) | CLI framework |
| [fatih/color](https://github.com/fatih/color) | Terminal color output |
| [olekukonko/tablewriter](https://github.com/olekukonko/tablewriter) | Table rendering |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-scanner`)
3. Commit your changes (`git commit -m 'Add new scanner'`)
4. Push to the branch (`git push origin feature/new-scanner`)
5. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE) for details.

# 🛡️ snow-vuln-tui

A terminal-based UI (TUI) for creating **Vulnerability Management tickets** in ServiceNow — built with Go and the [Charm](https://charm.sh) library stack.

No browser, no bloated GUI — just a clean, fast, keyboard-driven form that talks directly to the ServiceNow REST API.

## Features

- **Interactive TUI form** — multi-page wizard with validation, powered by [huh](https://github.com/charmbracelet/huh)
- **Basic authentication** — credentials are prompted at startup and never written to disk
- **Ticket creation** — POSTs to the `x_delr2_vulner_vulnerability_management` table
- **File attachments** — upload one or more files after ticket creation via the ServiceNow Attachment API
- **Progress spinner** — visual feedback during API calls
- **Confirmation step** — review a summary before submitting
- **Customisable instance** — defaults to `deluxeprod.service-now.com`, override with `--instance`

## Installation

### From source

```bash
git clone https://github.com/bob-the-glitch/snow-vuln-tui.git
cd snow-vuln-tui
go build -o snow-vuln-tui .
```

### With `go install`

```bash
go install github.com/bob-the-glitch/snow-vuln-tui@latest
```

> **Requires Go 1.21 or later.**

## Usage

```bash
# Default instance (deluxeprod.service-now.com)
./snow-vuln-tui

# Custom ServiceNow instance
./snow-vuln-tui --instance mycompany.service-now.com
```

### TUI Flow

1. **Authentication** — enter your ServiceNow username and password (masked input)
2. **Classification** — select Severity (Critical / High / Medium / Low) and State (Open / In Progress / Closed)
3. **Details** — enter short description and a multi-line description
4. **Assignment & Dates** — set assignment group, caller, due date, and modification date
5. **Attachments** — optionally provide comma-separated file paths
6. **Confirmation** — review the ticket summary and confirm submission
7. **Result** — see the created ticket number and sys_id, plus attachment upload status

## Form Fields

| Field              | Type       | Default                         | Required |
| ------------------ | ---------- | ------------------------------- | -------- |
| Severity           | Select     | —                               | Yes      |
| State              | Select     | —                               | Yes      |
| Short Description  | Text       | —                               | Yes      |
| Assignment Group   | Text       | `Enterprise_Services_HDS_GCO`   | No       |
| Description        | Text Area  | —                               | Yes      |
| Caller             | Text       | `Security Service Account`      | No       |
| Due Date           | Text       | —                               | No       |
| Modification Date  | Text       | Today's date                    | No       |
| Attachments        | Text       | —                               | No       |

## API Endpoints Used

### Create Ticket
```
POST https://{instance}/api/now/table/x_delr2_vulner_vulnerability_management
Content-Type: application/json
Authorization: Basic <base64>
```

### Upload Attachment
```
POST https://{instance}/api/now/attachment/file
  ?table_name=x_delr2_vulner_vulnerability_management
  &table_sys_id={sys_id}
  &file_name={filename}
Content-Type: <detected mime type>
Authorization: Basic <base64>
```

## Requirements

- **Go 1.21+**
- A ServiceNow instance with the `x_delr2_vulner_vulnerability_management` table
- Valid ServiceNow credentials with permission to create records and upload attachments

## Tech Stack

- [bubbletea](https://github.com/charmbracelet/bubbletea) — TUI framework
- [huh](https://github.com/charmbracelet/huh) — form components
- [lipgloss](https://github.com/charmbracelet/lipgloss) — terminal styling
- [bubbles](https://github.com/charmbracelet/bubbles) — spinner and other TUI components

## License

MIT

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/bob-the-glitch/snow-vuln-tui/internal/auth"
	"github.com/bob-the-glitch/snow-vuln-tui/internal/form"
	"github.com/bob-the-glitch/snow-vuln-tui/internal/models"
	"github.com/bob-the-glitch/snow-vuln-tui/internal/snow"
)

// ── Styles ──────────────────────────────────────────────────────────────────

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7D56F4")).
			MarginTop(1).
			MarginBottom(1)

	successStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#04B575"))

	errorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FF4672"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666"))

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7D56F4")).
			Padding(1, 2).
			MarginTop(1)
)

// ── Spinner model (for ticket submission) ───────────────────────────────────

type phase int

const (
	phaseCreating phase = iota
	phaseUploading
	phaseDone
)

type submitModel struct {
	spinner    spinner.Model
	phase      phase
	client     *snow.Client
	ticket     *models.Ticket
	result     *models.CreateResponse
	uploaded   []string
	errMsg     string
	quitting   bool
	attachIdx  int
}

type ticketCreatedMsg struct {
	resp *models.CreateResponse
	err  error
}

type attachmentUploadedMsg struct {
	name string
	err  error
}

func newSubmitModel(client *snow.Client, ticket *models.Ticket) submitModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4"))
	return submitModel{
		spinner: s,
		client:  client,
		ticket:  ticket,
	}
}

func (m submitModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, m.createTicket())
}

func (m submitModel) createTicket() tea.Cmd {
	return func() tea.Msg {
		resp, err := m.client.CreateTicket(m.ticket)
		return ticketCreatedMsg{resp: resp, err: err}
	}
}

func (m submitModel) uploadNext() tea.Cmd {
	idx := m.attachIdx
	sysID := m.result.Result.SysID
	path := m.ticket.Attachments[idx]
	return func() tea.Msg {
		resp, err := m.client.UploadAttachment(sysID, path)
		if err != nil {
			return attachmentUploadedMsg{name: path, err: err}
		}
		return attachmentUploadedMsg{name: resp.Result.FileName, err: nil}
	}
}

func (m submitModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" || msg.String() == "enter" {
			if m.phase == phaseDone || m.errMsg != "" {
				m.quitting = true
				return m, tea.Quit
			}
		}
		return m, nil

	case ticketCreatedMsg:
		if msg.err != nil {
			m.errMsg = msg.err.Error()
			return m, nil
		}
		m.result = msg.resp
		if len(m.ticket.Attachments) > 0 {
			m.phase = phaseUploading
			m.attachIdx = 0
			return m, m.uploadNext()
		}
		m.phase = phaseDone
		return m, nil

	case attachmentUploadedMsg:
		if msg.err != nil {
			m.errMsg = fmt.Sprintf("attachment error: %s", msg.err)
			m.phase = phaseDone
			return m, nil
		}
		m.uploaded = append(m.uploaded, msg.name)
		m.attachIdx++
		if m.attachIdx < len(m.ticket.Attachments) {
			return m, m.uploadNext()
		}
		m.phase = phaseDone
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m submitModel) View() string {
	if m.errMsg != "" {
		return boxStyle.Render(
			errorStyle.Render("✗ Error") + "\n\n" +
				m.errMsg + "\n\n" +
				dimStyle.Render("Press q or Enter to exit."),
		) + "\n"
	}

	if m.phase == phaseDone {
		var sb strings.Builder
		sb.WriteString(successStyle.Render("✓ Ticket Created Successfully!"))
		sb.WriteString("\n\n")
		if m.result != nil {
			sb.WriteString(fmt.Sprintf("  Number:  %s\n", valueOrNA(m.result.Result.Number)))
			sb.WriteString(fmt.Sprintf("  Sys ID:  %s\n", m.result.Result.SysID))
		}
		if len(m.uploaded) > 0 {
			sb.WriteString(fmt.Sprintf("\n  📎 %d attachment(s) uploaded:\n", len(m.uploaded)))
			for _, name := range m.uploaded {
				sb.WriteString(fmt.Sprintf("     • %s\n", name))
			}
		}
		sb.WriteString("\n")
		sb.WriteString(dimStyle.Render("Press q or Enter to exit."))
		return boxStyle.Render(sb.String()) + "\n"
	}

	label := "Creating ticket…"
	if m.phase == phaseUploading {
		label = fmt.Sprintf("Uploading attachment %d/%d…", m.attachIdx+1, len(m.ticket.Attachments))
	}
	return fmt.Sprintf("\n  %s %s\n", m.spinner.View(), label)
}

func valueOrNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}

// ── Severity label helper ───────────────────────────────────────────────────

func severityLabel(code string) string {
	switch code {
	case "1":
		return "Critical"
	case "2":
		return "High"
	case "3":
		return "Medium"
	case "4":
		return "Low"
	default:
		return code
	}
}

func stateLabel(code string) string {
	switch code {
	case "1":
		return "Open"
	case "2":
		return "In Progress"
	case "3":
		return "Closed"
	default:
		return code
	}
}

// ── Main ────────────────────────────────────────────────────────────────────

func main() {
	instance := flag.String("instance", "deluxeprod.service-now.com", "ServiceNow instance hostname")
	flag.Parse()

	// Banner
	banner := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#7D56F4")).
		Render("╔══════════════════════════════════════════════╗\n" +
			"║   🛡️  SNOW Vulnerability Ticket Creator  🛡️   ║\n" +
			"╚══════════════════════════════════════════════╝")
	fmt.Println(banner)
	fmt.Println(dimStyle.Render(fmt.Sprintf("  Instance: %s\n", *instance)))

	// ── Step 1: Authenticate ────────────────────────────────────────
	creds, err := auth.Prompt()
	if err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("✗ %s", err)))
		os.Exit(1)
	}
	fmt.Println(successStyle.Render("  ✓ Credentials accepted\n"))

	// ── Step 2: Fill ticket form ────────────────────────────────────
	ticket, err := form.Run()
	if err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("\n✗ %s", err)))
		os.Exit(1)
	}

	// ── Step 3: Print summary ───────────────────────────────────────
	summaryStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#7D56F4")).
		Padding(1, 2)

	var summary strings.Builder
	summary.WriteString(titleStyle.Render("Ticket Summary") + "\n\n")
	summary.WriteString(fmt.Sprintf("  Severity:          %s\n", severityLabel(ticket.Severity)))
	summary.WriteString(fmt.Sprintf("  State:             %s\n", stateLabel(ticket.State)))
	summary.WriteString(fmt.Sprintf("  Short Description: %s\n", ticket.ShortDescription))
	summary.WriteString(fmt.Sprintf("  Assignment Group:  %s\n", ticket.AssignmentGroup))
	summary.WriteString(fmt.Sprintf("  Caller:            %s\n", ticket.Caller))
	summary.WriteString(fmt.Sprintf("  Due Date:          %s\n", valueOrNA(ticket.DueDate)))
	summary.WriteString(fmt.Sprintf("  Modification Date: %s\n", valueOrNA(ticket.ModificationDate)))
	if len(ticket.Attachments) > 0 {
		summary.WriteString(fmt.Sprintf("  Attachments:       %d file(s)\n", len(ticket.Attachments)))
	}
	summary.WriteString(fmt.Sprintf("\n  Description:\n  %s\n",
		dimStyle.Render(truncate(ticket.Description, 200))))

	fmt.Println(summaryStyle.Render(summary.String()))
	fmt.Println()

	// ── Step 4: Submit ──────────────────────────────────────────────
	_ = time.Now() // keep time import used
	client := snow.NewClient(*instance, creds)
	m := newSubmitModel(client, ticket)

	p := tea.NewProgram(m)
	if _, err := p.Run(); err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("✗ Fatal: %s", err)))
		os.Exit(1)
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

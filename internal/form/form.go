package form

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/trevorcapps/snow-vuln-tui/internal/models"
)

// Run displays the vulnerability ticket form and returns the populated ticket.
func Run() (*models.Ticket, error) {
	ticket := &models.Ticket{
		AssignmentGroup:  "Enterprise_Services_HDS_GCO",
		Caller:           "Security Service Account",
		ModificationDate: time.Now().Format("2006-01-02"),
	}

	var attachmentsRaw string
	var confirm bool

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#7D56F4")).
		MarginBottom(1)

	fmt.Println(titleStyle.Render("📋 New Vulnerability Management Ticket"))
	fmt.Println()

	form := huh.NewForm(
		// ── Page 1: Classification ──────────────────────────────────
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Severity").
				Options(
					huh.NewOption("Critical", "1"),
					huh.NewOption("High", "2"),
					huh.NewOption("Medium", "3"),
					huh.NewOption("Low", "4"),
				).
				Value(&ticket.Severity),

			huh.NewSelect[string]().
				Title("State").
				Options(
					huh.NewOption("Open", "1"),
					huh.NewOption("In Progress", "2"),
					huh.NewOption("Closed", "3"),
				).
				Value(&ticket.State),
		).Title("Classification"),

		// ── Page 2: Details ─────────────────────────────────────────
		huh.NewGroup(
			huh.NewInput().
				Title("Short Description").
				Placeholder("Brief summary of the vulnerability").
				Value(&ticket.ShortDescription).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("short description is required")
					}
					return nil
				}),

			huh.NewText().
				Title("Description").
				Placeholder("Detailed description of the vulnerability…").
				CharLimit(4000).
				Value(&ticket.Description).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("description is required")
					}
					return nil
				}),
		).Title("Details"),

		// ── Page 3: Assignment & Dates ──────────────────────────────
		huh.NewGroup(
			huh.NewInput().
				Title("Assignment Group").
				Value(&ticket.AssignmentGroup),

			huh.NewInput().
				Title("Caller").
				Value(&ticket.Caller),

			huh.NewInput().
				Title("Due Date").
				Placeholder("YYYY-MM-DD").
				Value(&ticket.DueDate).
				Validate(func(s string) error {
					if s == "" {
						return nil // optional
					}
					_, err := time.Parse("2006-01-02", s)
					if err != nil {
						return fmt.Errorf("invalid date format – use YYYY-MM-DD")
					}
					return nil
				}),

			huh.NewInput().
				Title("Modification Date").
				Placeholder("YYYY-MM-DD").
				Value(&ticket.ModificationDate).
				Validate(func(s string) error {
					if s == "" {
						return nil
					}
					_, err := time.Parse("2006-01-02", s)
					if err != nil {
						return fmt.Errorf("invalid date format – use YYYY-MM-DD")
					}
					return nil
				}),
		).Title("Assignment & Dates"),

		// ── Page 4: Attachments ─────────────────────────────────────
		huh.NewGroup(
			huh.NewInput().
				Title("Attachments").
				Description("Comma-separated file paths (optional)").
				Placeholder("/path/to/report.pdf, /path/to/scan.csv").
				Value(&attachmentsRaw),
		).Title("Attachments"),

		// ── Page 5: Confirm ─────────────────────────────────────────
		huh.NewGroup(
			huh.NewConfirm().
				Title("Submit this ticket?").
				Affirmative("Yes, submit").
				Negative("Cancel").
				Value(&confirm),
		).Title("Confirmation"),
	)

	err := form.Run()
	if err != nil {
		return nil, fmt.Errorf("form cancelled: %w", err)
	}

	if !confirm {
		return nil, fmt.Errorf("submission cancelled by user")
	}

	// Parse attachments.
	if strings.TrimSpace(attachmentsRaw) != "" {
		for _, p := range strings.Split(attachmentsRaw, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				ticket.Attachments = append(ticket.Attachments, p)
			}
		}
	}

	return ticket, nil
}

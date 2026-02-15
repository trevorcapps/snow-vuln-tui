package auth

import (
	"encoding/base64"
	"fmt"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// Credentials holds the ServiceNow username and password (never written to disk).
type Credentials struct {
	Username string
	Password string
}

// BasicHeader returns the HTTP Basic Authorization header value.
func (c *Credentials) BasicHeader() string {
	raw := fmt.Sprintf("%s:%s", c.Username, c.Password)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(raw))
}

// Prompt displays a TUI form asking for ServiceNow credentials.
func Prompt() (*Credentials, error) {
	creds := &Credentials{}

	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#7D56F4")).
		MarginBottom(1)

	fmt.Println(headerStyle.Render("🔐 ServiceNow Authentication"))
	fmt.Println(lipgloss.NewStyle().Foreground(lipgloss.Color("#666")).Render("Credentials are used for this session only and are never stored to disk.\n"))

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Username").
				Placeholder("your.username").
				Value(&creds.Username).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("username is required")
					}
					return nil
				}),
			huh.NewInput().
				Title("Password").
				Placeholder("••••••••").
				EchoMode(huh.EchoModePassword).
				Value(&creds.Password).
				Validate(func(s string) error {
					if s == "" {
						return fmt.Errorf("password is required")
					}
					return nil
				}),
		),
	)

	err := form.Run()
	if err != nil {
		return nil, fmt.Errorf("authentication cancelled: %w", err)
	}

	return creds, nil
}

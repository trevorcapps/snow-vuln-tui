package snow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/bob-the-glitch/snow-vuln-tui/internal/auth"
	"github.com/bob-the-glitch/snow-vuln-tui/internal/models"
)

const (
	tableName = "x_delr2_vulner_vulnerability_management"
)

// Client is a ServiceNow REST API client.
type Client struct {
	Instance   string
	Creds      *auth.Credentials
	HTTPClient *http.Client
}

// NewClient creates a new ServiceNow API client.
func NewClient(instance string, creds *auth.Credentials) *Client {
	return &Client{
		Instance: instance,
		Creds:    creds,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) baseURL() string {
	return fmt.Sprintf("https://%s", c.Instance)
}

// CreateTicket posts a new vulnerability management ticket and returns the response.
func (c *Client) CreateTicket(ticket *models.Ticket) (*models.CreateResponse, error) {
	endpoint := fmt.Sprintf("%s/api/now/table/%s", c.baseURL(), tableName)

	// Build the JSON payload from the ticket fields.
	payload := map[string]string{
		"severity":          ticket.Severity,
		"state":             ticket.State,
		"short_description": ticket.ShortDescription,
		"assignment_group":  ticket.AssignmentGroup,
		"description":       ticket.Description,
		"caller_id":         ticket.Caller,
		"due_date":          ticket.DueDate,
	}
	if ticket.ModificationDate != "" {
		payload["u_modification_date"] = ticket.ModificationDate
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ticket: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.Creds.BasicHeader())

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ServiceNow API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result models.CreateResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// UploadAttachment uploads a single file to an existing ticket record.
func (c *Client) UploadAttachment(sysID, filePath string) (*models.AttachmentResponse, error) {
	fileName := filepath.Base(filePath)

	params := url.Values{}
	params.Set("table_name", tableName)
	params.Set("table_sys_id", sysID)
	params.Set("file_name", fileName)

	endpoint := fmt.Sprintf("%s/api/now/attachment/file?%s", c.baseURL(), params.Encode())

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("cannot open file %q: %w", filePath, err)
	}
	defer f.Close()

	req, err := http.NewRequest(http.MethodPost, endpoint, f)
	if err != nil {
		return nil, fmt.Errorf("failed to build attachment request: %w", err)
	}

	// Detect MIME type from extension; fall back to octet-stream.
	contentType := mime.TypeByExtension(filepath.Ext(filePath))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.Creds.BasicHeader())

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error uploading %q: %w", fileName, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read attachment response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("attachment upload error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result models.AttachmentResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse attachment response: %w", err)
	}

	return &result, nil
}

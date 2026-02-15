package models

// Ticket represents a vulnerability management ticket in ServiceNow.
type Ticket struct {
	Severity         string   `json:"severity"`
	State            string   `json:"state"`
	ShortDescription string   `json:"short_description"`
	AssignmentGroup  string   `json:"assignment_group"`
	Description      string   `json:"description"`
	Caller           string   `json:"caller_id"`
	DueDate          string   `json:"due_date"`
	ModificationDate string   `json:"sys_mod_count,omitempty"`
	Attachments      []string `json:"-"`
}

// CreateResponse is the relevant portion of the ServiceNow table API response.
type CreateResponse struct {
	Result struct {
		SysID  string `json:"sys_id"`
		Number string `json:"number"`
	} `json:"result"`
}

// AttachmentResponse is the relevant portion of the attachment API response.
type AttachmentResponse struct {
	Result struct {
		SysID    string `json:"sys_id"`
		FileName string `json:"file_name"`
	} `json:"result"`
}

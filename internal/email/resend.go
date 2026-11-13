package email

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"
)

// Resend sends through a Resend-compatible POST /emails: Resend itself
// (https://api.resend.com) or MillionSend (https://api.millionsend.com, or
// a self-hosted instance), which implements the same request, response and
// Idempotency-Key semantics.
type Resend struct {
	provider string
	baseURL  string
	apiKey   string
	from     string
	client   *http.Client
}

func NewResend(provider, baseURL, apiKey, from string, client *http.Client) (*Resend, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if provider == "" || !strings.HasPrefix(baseURL, "https://") && !strings.HasPrefix(baseURL, "http://") || apiKey == "" || strings.ContainsAny(apiKey, "\r\n") || client == nil {
		return nil, errors.New("email sender is misconfigured")
	}
	if _, err := mail.ParseAddress(from); err != nil || strings.ContainsAny(from, "\r\n") {
		return nil, errors.New("email sender address is invalid")
	}
	return &Resend{provider: provider, baseURL: baseURL, apiKey: apiKey, from: from, client: client}, nil
}

func (r *Resend) Provider() string { return r.provider }

func (r *Resend) Send(ctx context.Context, message Message, key string) error {
	rendered, err := Render(message)
	if err != nil {
		return err
	}
	if !validKey(key) {
		return ErrInvalidMessage
	}
	body, err := json.Marshal(map[string]any{"from": r.from, "to": []string{message.To}, "subject": rendered.Subject, "html": rendered.HTML, "text": rendered.Text})
	if err != nil {
		return ErrInvalidMessage
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+"/emails", bytes.NewReader(body))
	if err != nil {
		return &DeliveryError{Provider: r.provider, Permanent: true}
	}
	request.Header.Set("Authorization", "Bearer "+r.apiKey)
	request.Header.Set("Idempotency-Key", key)
	request.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return &DeliveryError{Provider: r.provider}
	}
	data := drain(response.Body)
	var failure struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(data, &failure)
	code := safeCode(failure.Name)
	// A concurrent request with the same key is still in flight; the retry
	// returns its result.
	if response.StatusCode == http.StatusConflict && code == "concurrent_idempotent_requests" {
		return &DeliveryError{Provider: r.provider, Status: response.StatusCode, Code: code}
	}
	return classifyHTTP(r.provider, response, code)
}

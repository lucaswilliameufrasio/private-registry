package email

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// Sabia sends through Sabiá's POST /v1/messages. Sabiá renders the
// templates published from sabia/templates.json and picks the sender from
// the application's channel profile.
type Sabia struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func NewSabia(baseURL, apiKey string, client *http.Client) (*Sabia, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if !strings.HasPrefix(baseURL, "https://") && !strings.HasPrefix(baseURL, "http://") || apiKey == "" || strings.ContainsAny(apiKey, "\r\n") || client == nil {
		return nil, errors.New("Sabiá email sender is misconfigured")
	}
	return &Sabia{baseURL: baseURL, apiKey: apiKey, client: client}, nil
}

func (s *Sabia) Provider() string { return "sabia" }

func (s *Sabia) Send(ctx context.Context, message Message, key string) error {
	if err := message.Validate(); err != nil {
		return err
	}
	if !validKey(key) {
		return ErrInvalidMessage
	}
	body, err := json.Marshal(map[string]any{"channel": "email", "to": message.To, "template": string(message.Template), "locale": Locale, "message_type": "transactional", "data": message.Data})
	if err != nil {
		return ErrInvalidMessage
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return &DeliveryError{Provider: s.Provider(), Permanent: true}
	}
	request.Header.Set("Authorization", "Bearer "+s.apiKey)
	request.Header.Set("Idempotency-Key", key)
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return &DeliveryError{Provider: s.Provider()}
	}
	data := drain(response.Body)
	var failure struct {
		Code string `json:"error_code"`
	}
	_ = json.Unmarshal(data, &failure)
	return classifyHTTP(s.Provider(), response, safeCode(failure.Code))
}

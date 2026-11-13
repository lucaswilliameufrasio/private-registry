package email

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Sender hands one message to a provider. key is stable for the message
// across retries, so providers that support idempotency deliver it once.
type Sender interface {
	Send(ctx context.Context, message Message, key string) error
	Provider() string
}

// DeliveryError explains a failed hand-off without carrying provider
// response bodies, which may echo recipients or links.
type DeliveryError struct {
	Provider   string
	Status     int
	Code       string
	Permanent  bool
	RetryAfter time.Duration
}

func (e *DeliveryError) Error() string {
	kind := "temporary"
	if e.Permanent {
		kind = "permanent"
	}
	if e.Code != "" {
		return fmt.Sprintf("%s rejected the message (%s, HTTP %d, %s)", e.Provider, kind, e.Status, e.Code)
	}
	if e.Status != 0 {
		return fmt.Sprintf("%s rejected the message (%s, HTTP %d)", e.Provider, kind, e.Status)
	}
	return fmt.Sprintf("%s could not be reached (%s)", e.Provider, kind)
}

// IsPermanent reports whether retrying err cannot succeed.
func IsPermanent(err error) bool {
	var delivery *DeliveryError
	return errors.Is(err, ErrInvalidMessage) || (errors.As(err, &delivery) && delivery.Permanent)
}

// retryAfter returns the delay a provider asked for, if any.
func retryAfter(err error) time.Duration {
	var delivery *DeliveryError
	if errors.As(err, &delivery) {
		return delivery.RetryAfter
	}
	return 0
}

const (
	sendTimeout      = 15 * time.Second
	maxResponseBytes = 16 << 10
)

// classifyHTTP turns a provider response into nil or a DeliveryError: 429,
// 5xx and 408 are retried; other rejections are configuration or integration
// errors that retrying does not fix.
func classifyHTTP(provider string, response *http.Response, code string) error {
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	err := &DeliveryError{Provider: provider, Status: response.StatusCode, Code: code}
	switch {
	case response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= 500:
		if seconds, parseErr := strconv.Atoi(strings.TrimSpace(response.Header.Get("Retry-After"))); parseErr == nil && seconds > 0 {
			err.RetryAfter = min(time.Duration(seconds)*time.Second, time.Hour)
		}
	default:
		err.Permanent = true
	}
	return err
}

func drain(body io.ReadCloser) []byte {
	defer body.Close()
	data, _ := io.ReadAll(io.LimitReader(body, maxResponseBytes))
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 1<<20))
	return data
}

// safeCode keeps an error code only when it is a short identifier, so a
// provider cannot smuggle message content into logs.
func safeCode(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return ""
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return ""
		}
	}
	return value
}

func validKey(key string) bool {
	if len(key) < 1 || len(key) > 200 {
		return false
	}
	for _, r := range key {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

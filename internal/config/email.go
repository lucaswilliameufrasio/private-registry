package config

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"strconv"
	"strings"
)

// EmailProvider names where the registry hands its messages.
type EmailProvider string

const (
	EmailDisabled    EmailProvider = ""
	EmailSabia       EmailProvider = "sabia"
	EmailResend      EmailProvider = "resend"
	EmailMillionSend EmailProvider = "millionsend"
	EmailSMTP        EmailProvider = "smtp"
)

// EmailConfig enables transactional email. HTTP providers (Sabiá, Resend,
// MillionSend) and SMTP use the same outbound rules as other integrations:
// explicit networks, optional explicit DNS server and CA bundle.
type EmailConfig struct {
	Provider EmailProvider
	// From is the sender for Resend, MillionSend and SMTP. Sabiá uses the
	// sender of its channel profile.
	From string
	// APIOrigin and APIKeyFile are for the HTTP providers.
	APIOrigin  string
	APIKeyFile string
	// SMTP settings.
	SMTPAddress      string
	SMTPSecurity     string
	SMTPUsername     string
	SMTPPasswordFile string

	AllowedNetworks []netip.Prefix
	DNSServer       netip.AddrPort
	CAFile          string
}

var emailKeys = []string{
	"REGISTRY_EMAIL_FROM", "REGISTRY_EMAIL_API_ORIGIN", "REGISTRY_EMAIL_API_KEY_FILE",
	"REGISTRY_EMAIL_SMTP_ADDRESS", "REGISTRY_EMAIL_SMTP_SECURITY", "REGISTRY_EMAIL_SMTP_USERNAME", "REGISTRY_EMAIL_SMTP_PASSWORD_FILE",
	"REGISTRY_EMAIL_ALLOWED_NETWORKS", "REGISTRY_EMAIL_DNS_SERVER", "REGISTRY_EMAIL_CA_FILE",
}

func loadEmail(lookup LookupEnv) (EmailConfig, error) {
	raw, enabled := lookup("REGISTRY_EMAIL_PROVIDER")
	if !enabled {
		for _, key := range emailKeys {
			if _, exists := lookup(key); exists {
				return EmailConfig{}, fmt.Errorf("%s requires REGISTRY_EMAIL_PROVIDER", key)
			}
		}
		return EmailConfig{}, nil
	}
	cfg := EmailConfig{Provider: EmailProvider(raw)}
	forbid := func(keys ...string) error {
		for _, key := range keys {
			if _, exists := lookup(key); exists {
				return fmt.Errorf("%s is not used with REGISTRY_EMAIL_PROVIDER=%s", key, raw)
			}
		}
		return nil
	}
	var err error
	switch cfg.Provider {
	case EmailSabia, EmailResend, EmailMillionSend:
		if err := forbid("REGISTRY_EMAIL_SMTP_ADDRESS", "REGISTRY_EMAIL_SMTP_SECURITY", "REGISTRY_EMAIL_SMTP_USERNAME", "REGISTRY_EMAIL_SMTP_PASSWORD_FILE"); err != nil {
			return EmailConfig{}, err
		}
		defaults := map[EmailProvider]string{EmailResend: "https://api.resend.com", EmailMillionSend: "https://api.millionsend.com"}
		if _, exists := lookup("REGISTRY_EMAIL_API_ORIGIN"); exists || cfg.Provider == EmailSabia {
			if cfg.APIOrigin, err = requiredHTTPSOrigin(lookup, "REGISTRY_EMAIL_API_ORIGIN"); err != nil {
				return EmailConfig{}, err
			}
		} else {
			cfg.APIOrigin = defaults[cfg.Provider]
		}
		if cfg.APIKeyFile, err = requiredFilePath(lookup, "REGISTRY_EMAIL_API_KEY_FILE"); err != nil {
			return EmailConfig{}, err
		}
		if cfg.Provider == EmailSabia {
			if err := forbid("REGISTRY_EMAIL_FROM"); err != nil {
				return EmailConfig{}, errors.New("REGISTRY_EMAIL_FROM is not used with Sabiá: the sender comes from the Sabiá channel profile")
			}
		}
	case EmailSMTP:
		if err := forbid("REGISTRY_EMAIL_API_ORIGIN", "REGISTRY_EMAIL_API_KEY_FILE"); err != nil {
			return EmailConfig{}, err
		}
		if cfg.SMTPAddress, err = required(lookup, "REGISTRY_EMAIL_SMTP_ADDRESS"); err != nil {
			return EmailConfig{}, err
		}
		host, port, splitErr := net.SplitHostPort(cfg.SMTPAddress)
		number, portErr := strconv.Atoi(port)
		if splitErr != nil || host == "" || portErr != nil || number < 1 || number > 65535 {
			return EmailConfig{}, errors.New("REGISTRY_EMAIL_SMTP_ADDRESS must be host:port")
		}
		cfg.SMTPSecurity, err = value(lookup, "REGISTRY_EMAIL_SMTP_SECURITY", "starttls")
		if err != nil {
			return EmailConfig{}, err
		}
		switch cfg.SMTPSecurity {
		case "starttls", "tls":
		case "none":
			if address, err := netip.ParseAddr(host); err != nil || !address.IsLoopback() {
				return EmailConfig{}, errors.New("REGISTRY_EMAIL_SMTP_SECURITY=none is allowed only for a loopback IP address, such as Mailpit in development")
			}
		default:
			return EmailConfig{}, errors.New("REGISTRY_EMAIL_SMTP_SECURITY must be starttls, tls or none")
		}
		_, hasUser := lookup("REGISTRY_EMAIL_SMTP_USERNAME")
		_, hasPassword := lookup("REGISTRY_EMAIL_SMTP_PASSWORD_FILE")
		if hasUser != hasPassword {
			return EmailConfig{}, errors.New("REGISTRY_EMAIL_SMTP_USERNAME and REGISTRY_EMAIL_SMTP_PASSWORD_FILE must be set together")
		}
		if hasUser {
			if cfg.SMTPUsername, err = required(lookup, "REGISTRY_EMAIL_SMTP_USERNAME"); err != nil {
				return EmailConfig{}, err
			}
			if cfg.SMTPPasswordFile, err = requiredFilePath(lookup, "REGISTRY_EMAIL_SMTP_PASSWORD_FILE"); err != nil {
				return EmailConfig{}, err
			}
		}
	default:
		return EmailConfig{}, errors.New("REGISTRY_EMAIL_PROVIDER must be sabia, resend, millionsend or smtp")
	}
	if cfg.Provider != EmailSabia {
		if cfg.From, err = required(lookup, "REGISTRY_EMAIL_FROM"); err != nil {
			return EmailConfig{}, err
		}
		if _, err := mail.ParseAddress(cfg.From); err != nil || strings.ContainsAny(cfg.From, "\r\n") {
			return EmailConfig{}, errors.New("REGISTRY_EMAIL_FROM must be an email address, optionally with a name: Registry <registry@example.com>")
		}
	}
	if cfg.AllowedNetworks, err = requiredNetworks(lookup, "REGISTRY_EMAIL_ALLOWED_NETWORKS"); err != nil {
		return EmailConfig{}, err
	}
	if cfg.DNSServer, err = optionalDNSServer(lookup, "REGISTRY_EMAIL_DNS_SERVER"); err != nil {
		return EmailConfig{}, err
	}
	if _, exists := lookup("REGISTRY_EMAIL_CA_FILE"); exists {
		if cfg.CAFile, err = requiredFilePath(lookup, "REGISTRY_EMAIL_CA_FILE"); err != nil {
			return EmailConfig{}, err
		}
	}
	return cfg, nil
}

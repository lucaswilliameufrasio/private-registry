package config

import "testing"

func TestEmailConfiguration(t *testing.T) {
	cfg, err := LoadFrom(lookupMap(nil))
	if err != nil || cfg.Email.Provider != EmailDisabled {
		t.Fatalf("email must be off by default: %+v %v", cfg.Email, err)
	}
	valid := []map[string]string{
		{"REGISTRY_EMAIL_PROVIDER": "sabia", "REGISTRY_EMAIL_API_ORIGIN": "https://sabia.example", "REGISTRY_EMAIL_API_KEY_FILE": "/run/secrets/sabia", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "203.0.113.0/24"},
		{"REGISTRY_EMAIL_PROVIDER": "resend", "REGISTRY_EMAIL_API_KEY_FILE": "/run/secrets/resend", "REGISTRY_EMAIL_FROM": "Registry <registry@example.com>", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "0.0.0.0/0", "REGISTRY_EMAIL_DNS_SERVER": "1.1.1.1:53"},
		{"REGISTRY_EMAIL_PROVIDER": "millionsend", "REGISTRY_EMAIL_API_KEY_FILE": "/run/secrets/ms", "REGISTRY_EMAIL_FROM": "registry@example.com", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "0.0.0.0/0", "REGISTRY_EMAIL_DNS_SERVER": "1.1.1.1:53"},
		{"REGISTRY_EMAIL_PROVIDER": "smtp", "REGISTRY_EMAIL_SMTP_ADDRESS": "127.0.0.1:1025", "REGISTRY_EMAIL_SMTP_SECURITY": "none", "REGISTRY_EMAIL_FROM": "registry@example.com", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "127.0.0.0/8"},
		{"REGISTRY_EMAIL_PROVIDER": "smtp", "REGISTRY_EMAIL_SMTP_ADDRESS": "smtp.example.com:587", "REGISTRY_EMAIL_SMTP_USERNAME": "registry", "REGISTRY_EMAIL_SMTP_PASSWORD_FILE": "/run/secrets/smtp", "REGISTRY_EMAIL_FROM": "registry@example.com", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "198.51.100.0/24", "REGISTRY_EMAIL_DNS_SERVER": "1.1.1.1:53"},
	}
	for _, values := range valid {
		cfg, err := LoadFrom(lookupMap(values))
		if err != nil {
			t.Fatalf("%v: %v", values, err)
		}
		if cfg.Email.Provider != EmailProvider(values["REGISTRY_EMAIL_PROVIDER"]) {
			t.Fatalf("provider %q", cfg.Email.Provider)
		}
	}
	cfg, _ = LoadFrom(lookupMap(valid[2]))
	if cfg.Email.APIOrigin != "https://api.millionsend.com" {
		t.Fatalf("MillionSend default origin: %q", cfg.Email.APIOrigin)
	}
	cfg, _ = LoadFrom(lookupMap(valid[4]))
	if cfg.Email.SMTPSecurity != "starttls" {
		t.Fatalf("SMTP must default to STARTTLS: %q", cfg.Email.SMTPSecurity)
	}
	invalid := []map[string]string{
		{"REGISTRY_EMAIL_FROM": "registry@example.com"},
		{"REGISTRY_EMAIL_PROVIDER": "sendgrid", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "0.0.0.0/0"},
		// Sabiá needs an explicit origin and takes the sender from its profile.
		{"REGISTRY_EMAIL_PROVIDER": "sabia", "REGISTRY_EMAIL_API_KEY_FILE": "/k", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "0.0.0.0/0"},
		{"REGISTRY_EMAIL_PROVIDER": "sabia", "REGISTRY_EMAIL_API_ORIGIN": "https://sabia.example", "REGISTRY_EMAIL_API_KEY_FILE": "/k", "REGISTRY_EMAIL_FROM": "a@example.com", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "0.0.0.0/0"},
		{"REGISTRY_EMAIL_PROVIDER": "resend", "REGISTRY_EMAIL_API_ORIGIN": "http://api.resend.com", "REGISTRY_EMAIL_API_KEY_FILE": "/k", "REGISTRY_EMAIL_FROM": "a@example.com", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "0.0.0.0/0"},
		{"REGISTRY_EMAIL_PROVIDER": "resend", "REGISTRY_EMAIL_API_KEY_FILE": "/k", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "0.0.0.0/0"},
		{"REGISTRY_EMAIL_PROVIDER": "resend", "REGISTRY_EMAIL_API_KEY_FILE": "/k", "REGISTRY_EMAIL_FROM": "a@example.com"},
		{"REGISTRY_EMAIL_PROVIDER": "smtp", "REGISTRY_EMAIL_SMTP_ADDRESS": "smtp.example.com:25", "REGISTRY_EMAIL_SMTP_SECURITY": "none", "REGISTRY_EMAIL_FROM": "a@example.com", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "0.0.0.0/0"},
		{"REGISTRY_EMAIL_PROVIDER": "smtp", "REGISTRY_EMAIL_SMTP_ADDRESS": "smtp.example.com", "REGISTRY_EMAIL_FROM": "a@example.com", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "0.0.0.0/0"},
		{"REGISTRY_EMAIL_PROVIDER": "smtp", "REGISTRY_EMAIL_SMTP_ADDRESS": "smtp.example.com:587", "REGISTRY_EMAIL_SMTP_USERNAME": "u", "REGISTRY_EMAIL_FROM": "a@example.com", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "0.0.0.0/0"},
		{"REGISTRY_EMAIL_PROVIDER": "smtp", "REGISTRY_EMAIL_SMTP_ADDRESS": "127.0.0.1:1025", "REGISTRY_EMAIL_API_KEY_FILE": "/k", "REGISTRY_EMAIL_FROM": "a@example.com", "REGISTRY_EMAIL_ALLOWED_NETWORKS": "127.0.0.0/8"},
	}
	for _, values := range invalid {
		if _, err := LoadFrom(lookupMap(values)); err == nil {
			t.Errorf("accepted %v", values)
		}
	}
}

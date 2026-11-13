package main

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"

	"private-registry/internal/config"
	"private-registry/internal/egress"
	"private-registry/internal/email"
	"private-registry/internal/secrets"
)

// openEmailSender builds the configured provider. Credentials come from
// private files and every connection goes through the egress rules.
func openEmailSender(cfg config.Config) (email.Sender, error) {
	roots, err := loadCertificatePool(cfg.Email.CAFile)
	if err != nil {
		return nil, errors.Join(errors.New("REGISTRY_EMAIL_CA_FILE could not be loaded"), err)
	}
	switch cfg.Email.Provider {
	case config.EmailSabia, config.EmailResend, config.EmailMillionSend:
		apiKey, err := secrets.LoadSecretFile(cfg.Email.APIKeyFile)
		if err != nil {
			return nil, errors.Join(errors.New("REGISTRY_EMAIL_API_KEY_FILE could not be read"), err)
		}
		destinations := []egress.Destination{{Origin: cfg.Email.APIOrigin, CIDRs: cfg.Email.AllowedNetworks}}
		var client *http.Client
		if cfg.Email.DNSServer.IsValid() {
			client, err = egress.NewHTTPSClientWithDNS(destinations, roots, cfg.Email.DNSServer)
		} else {
			client, err = egress.NewHTTPSClient(destinations, roots)
		}
		if err != nil {
			return nil, err
		}
		if cfg.Email.Provider == config.EmailSabia {
			return email.NewSabia(cfg.Email.APIOrigin, apiKey, client)
		}
		return email.NewResend(string(cfg.Email.Provider), cfg.Email.APIOrigin, apiKey, cfg.Email.From, client)
	case config.EmailSMTP:
		dialer, err := egress.NewTCPDialer(cfg.Email.SMTPAddress, cfg.Email.AllowedNetworks, cfg.Email.DNSServer)
		if err != nil {
			return nil, err
		}
		options := email.SMTPOptions{Security: email.SMTPSecurity(cfg.Email.SMTPSecurity), From: cfg.Email.From, Roots: roots}
		if cfg.Email.SMTPUsername != "" {
			password, err := secrets.LoadSecretFile(cfg.Email.SMTPPasswordFile)
			if err != nil {
				return nil, errors.Join(errors.New("REGISTRY_EMAIL_SMTP_PASSWORD_FILE could not be read"), err)
			}
			options.Username, options.Password = cfg.Email.SMTPUsername, password
		}
		if origin, err := url.Parse(cfg.CanonicalOrigin); err == nil && origin.Hostname() != "" {
			options.Hello = origin.Hostname()
			// RFC 5321 address literal for an IP origin.
			if address, err := netip.ParseAddr(options.Hello); err == nil {
				options.Hello = "[" + address.String() + "]"
				if address.Is6() {
					options.Hello = "[IPv6:" + address.String() + "]"
				}
			}
		}
		return email.NewSMTP(dialer, options)
	default:
		return nil, errors.New("email provider is not supported")
	}
}

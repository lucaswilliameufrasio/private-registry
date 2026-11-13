package email

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

// SMTPSecurity selects how the SMTP connection is protected.
type SMTPSecurity string

const (
	// SMTPStartTLS requires the server to offer STARTTLS before anything,
	// including credentials, is sent.
	SMTPStartTLS SMTPSecurity = "starttls"
	// SMTPImplicitTLS connects with TLS from the first byte (port 465).
	SMTPImplicitTLS SMTPSecurity = "tls"
	// SMTPPlain sends without TLS. It is accepted only for a loopback IP,
	// such as Mailpit in development.
	SMTPPlain SMTPSecurity = "none"
)

// Dialer opens the connection to the one configured SMTP server.
type Dialer interface {
	Dial(ctx context.Context) (net.Conn, error)
	Host() string
}

type SMTP struct {
	dialer   Dialer
	security SMTPSecurity
	from     *mail.Address
	username string
	password string
	roots    *x509.CertPool
	hello    string
}

type SMTPOptions struct {
	Security SMTPSecurity
	From     string
	Username string
	Password string
	// Roots verifies the server certificate; nil uses the system roots.
	Roots *x509.CertPool
	// Hello is the name announced in EHLO, normally the registry hostname.
	Hello string
}

func NewSMTP(dialer Dialer, options SMTPOptions) (*SMTP, error) {
	if dialer == nil {
		return nil, errors.New("SMTP email sender is misconfigured")
	}
	from, err := mail.ParseAddress(options.From)
	if err != nil || strings.ContainsAny(options.From, "\r\n") {
		return nil, errors.New("email sender address is invalid")
	}
	switch options.Security {
	case SMTPStartTLS, SMTPImplicitTLS:
	case SMTPPlain:
		address, err := netip.ParseAddr(dialer.Host())
		if err != nil || !address.IsLoopback() {
			return nil, errors.New("SMTP without TLS is allowed only to a loopback IP address")
		}
	default:
		return nil, errors.New("SMTP security must be starttls, tls or none")
	}
	if (options.Username == "") != (options.Password == "") || strings.ContainsAny(options.Username+options.Password, "\r\n") {
		return nil, errors.New("SMTP credentials need both a username and a password")
	}
	hello := options.Hello
	if hello == "" {
		hello = "localhost"
	}
	if strings.ContainsAny(hello, " \r\n") {
		return nil, errors.New("SMTP hello name is invalid")
	}
	return &SMTP{dialer: dialer, security: options.Security, from: from, username: options.Username, password: options.Password, roots: options.Roots, hello: hello}, nil
}

func (s *SMTP) Provider() string { return "smtp" }

func (s *SMTP) Send(ctx context.Context, message Message, key string) error {
	rendered, err := Render(message)
	if err != nil {
		return err
	}
	if !validKey(key) {
		return ErrInvalidMessage
	}
	body, err := s.compose(message.To, rendered, key)
	if err != nil {
		return ErrInvalidMessage
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	conn, err := s.dialer.Dial(ctx)
	if err != nil {
		return &DeliveryError{Provider: s.Provider()}
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	tlsConfig := &tls.Config{ServerName: s.dialer.Host(), MinVersion: tls.VersionTLS12, RootCAs: s.roots}
	if s.security == SMTPImplicitTLS {
		secured := tls.Client(conn, tlsConfig)
		if err := secured.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return &DeliveryError{Provider: s.Provider()}
		}
		conn = secured
	}
	client, err := smtp.NewClient(conn, s.dialer.Host())
	if err != nil {
		_ = conn.Close()
		return s.classify(err)
	}
	defer client.Close()
	if err := client.Hello(s.hello); err != nil {
		return s.classify(err)
	}
	if s.security == SMTPStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return &DeliveryError{Provider: s.Provider(), Code: "starttls_unavailable", Permanent: true}
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return &DeliveryError{Provider: s.Provider()}
		}
	}
	if s.username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.username, s.password, s.dialer.Host())); err != nil {
			return s.classify(err)
		}
	}
	if err := client.Mail(s.from.Address); err != nil {
		return s.classify(err)
	}
	if err := client.Rcpt(message.To); err != nil {
		return s.classify(err)
	}
	writer, err := client.Data()
	if err != nil {
		return s.classify(err)
	}
	if _, err := writer.Write(body); err != nil {
		_ = writer.Close()
		return &DeliveryError{Provider: s.Provider()}
	}
	if err := writer.Close(); err != nil {
		return s.classify(err)
	}
	_ = client.Quit()
	return nil
}

func (s *SMTP) classify(err error) error {
	var reply *textproto.Error
	if errors.As(err, &reply) {
		return &DeliveryError{Provider: s.Provider(), Code: fmt.Sprintf("smtp_%d", reply.Code), Permanent: reply.Code >= 500}
	}
	return &DeliveryError{Provider: s.Provider()}
}

// compose builds a multipart/alternative message. The Message-ID derives
// from the idempotency key, so a resend after a lost reply can be recognized
// as the same message.
func (s *SMTP) compose(to string, rendered Rendered, key string) ([]byte, error) {
	var boundary [12]byte
	if _, err := rand.Read(boundary[:]); err != nil {
		return nil, err
	}
	separator := "registry-" + hex.EncodeToString(boundary[:])
	digest := sha256.Sum256([]byte(key))
	domain := "private-registry.invalid"
	if _, host, found := strings.Cut(s.from.Address, "@"); found {
		domain = host
	}
	var out bytes.Buffer
	header := func(name, value string) { fmt.Fprintf(&out, "%s: %s\r\n", name, value) }
	header("From", s.from.String())
	header("To", to)
	header("Subject", mime.QEncoding.Encode("utf-8", rendered.Subject))
	header("Date", time.Now().UTC().Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(digest[:16])+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Auto-Submitted", "auto-generated")
	header("Content-Type", `multipart/alternative; boundary="`+separator+`"`)
	out.WriteString("\r\n")
	for _, part := range []struct{ kind, body string }{{"text/plain", rendered.Text}, {"text/html", rendered.HTML}} {
		fmt.Fprintf(&out, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", separator, part.kind)
		encoder := quotedprintable.NewWriter(&out)
		if _, err := encoder.Write([]byte(strings.ReplaceAll(part.body, "\n", "\r\n"))); err != nil {
			return nil, err
		}
		if err := encoder.Close(); err != nil {
			return nil, err
		}
		out.WriteString("\r\n")
	}
	fmt.Fprintf(&out, "--%s--\r\n", separator)
	return out.Bytes(), nil
}

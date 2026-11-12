// Package email delivers the registry's transactional messages: invitations,
// account recovery, address verification and security notices. Messages are
// written to a durable outbox in the transaction that needs them and a
// worker hands them to the configured provider: Sabiá renders its own
// published templates; Resend, MillionSend and SMTP (Mailpit in development)
// receive the subject and bodies rendered here from the same sources.
package email

import (
	"errors"
	"html"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Template identifies one transactional message. The key is also the Sabiá
// template key, so it follows Sabiá's naming rules.
type Template string

const (
	TemplateInvitation        Template = "registry.workspace-invitation"
	TemplateRecovery          Template = "registry.account-recovery"
	TemplateEmailVerification Template = "registry.email-verification"
	TemplateSecurityNotice    Template = "registry.security-notice"
)

// Locale is the only language the templates are written in.
const Locale = "pt-BR"

type variableType string

const (
	typeString variableType = "string"
	typeURL    variableType = "url"
)

type variable struct {
	Key     string
	Label   string
	Type    variableType
	Example string
}

type definition struct {
	ID      string
	Key     Template
	Name    string
	Subject string
	HTML    string
	Text    string
	Vars    []variable
}

const layoutStart = `<div style="font-family:Arial,Helvetica,sans-serif;background:#f6f7f9;padding:32px;color:#1d2733"><div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px">`
const layoutEnd = `<p style="margin:24px 0 0;color:#69737d;font-size:12px">Mensagem automática do registry privado. Não responda.</p></div></div>`

func button(label string) string {
	return `<p style="margin:24px 0"><a href="{{link}}" style="background:#1f5f99;color:#ffffff;padding:12px 20px;border-radius:8px;text-decoration:none;display:inline-block">` + label + `</a></p><p style="margin:0 0 16px;color:#69737d;font-size:13px;word-break:break-all">Se o botão não funcionar, copie este endereço: {{link}}</p>`
}

var definitions = []definition{
	{
		ID:      "private-registry-workspace-invitation-v1",
		Key:     TemplateInvitation,
		Name:    "Registry · convite para workspace",
		Subject: "Convite para o workspace {{workspace_name}}",
		HTML:    layoutStart + `<h1 style="margin:0 0 16px;font-size:20px">Você foi convidado</h1><p style="margin:0 0 8px;line-height:1.5">{{inviter_name}} convidou você para o workspace <strong>{{workspace_name}}</strong> como {{role_label}}.</p>` + button("Aceitar convite") + `<p style="margin:0;color:#69737d;font-size:13px">O convite vale até {{expires_at}} (UTC) e só pode ser usado uma vez. Se você não esperava este convite, ignore esta mensagem.</p>` + layoutEnd,
		Text:    "{{inviter_name}} convidou você para o workspace {{workspace_name}} como {{role_label}}.\n\nAceite o convite em:\n{{link}}\n\nO convite vale até {{expires_at}} (UTC) e só pode ser usado uma vez. Se você não esperava este convite, ignore esta mensagem.",
		Vars: []variable{
			{Key: "workspace_name", Label: "Nome do workspace", Type: typeString, Example: "Plataforma"},
			{Key: "inviter_name", Label: "Quem convidou", Type: typeString, Example: "Ana"},
			{Key: "role_label", Label: "Papel no workspace", Type: typeString, Example: "membro"},
			{Key: "link", Label: "Link do convite", Type: typeURL, Example: "https://registry.example/#/invite?token=prinv_example"},
			{Key: "expires_at", Label: "Validade (UTC)", Type: typeString, Example: "2026-11-19 12:00"},
		},
	},
	{
		ID:      "private-registry-account-recovery-v1",
		Key:     TemplateRecovery,
		Name:    "Registry · recuperação de conta",
		Subject: "Recuperação de acesso ao registry",
		HTML:    layoutStart + `<h1 style="margin:0 0 16px;font-size:20px">Recuperação de acesso</h1><p style="margin:0 0 8px;line-height:1.5">Olá, {{display_name}}. Recebemos um pedido para definir uma nova senha na sua conta.</p>` + button("Definir nova senha") + `<p style="margin:0;color:#69737d;font-size:13px">O link vale até {{expires_at}} (UTC) e só pode ser usado uma vez. Se você não fez esse pedido, ignore esta mensagem: sua senha atual continua valendo.</p>` + layoutEnd,
		Text:    "Olá, {{display_name}}. Recebemos um pedido para definir uma nova senha na sua conta.\n\nDefina a nova senha em:\n{{link}}\n\nO link vale até {{expires_at}} (UTC) e só pode ser usado uma vez. Se você não fez esse pedido, ignore esta mensagem: sua senha atual continua valendo.",
		Vars: []variable{
			{Key: "display_name", Label: "Nome da pessoa", Type: typeString, Example: "Ana"},
			{Key: "link", Label: "Link de recuperação", Type: typeURL, Example: "https://registry.example/#/recover?token=prrst_example"},
			{Key: "expires_at", Label: "Validade (UTC)", Type: typeString, Example: "2026-11-13 12:00"},
		},
	},
	{
		ID:      "private-registry-email-verification-v1",
		Key:     TemplateEmailVerification,
		Name:    "Registry · confirmação de e-mail",
		Subject: "Confirme seu e-mail no registry",
		HTML:    layoutStart + `<h1 style="margin:0 0 16px;font-size:20px">Confirme seu e-mail</h1><p style="margin:0 0 8px;line-height:1.5">Olá, {{display_name}}. Confirme que este endereço é seu para usá-lo na recuperação de acesso e nos avisos de segurança.</p>` + button("Confirmar e-mail") + `<p style="margin:0;color:#69737d;font-size:13px">O link vale até {{expires_at}} (UTC). Se você não pediu esta confirmação, ignore esta mensagem.</p>` + layoutEnd,
		Text:    "Olá, {{display_name}}. Confirme que este endereço é seu para usá-lo na recuperação de acesso e nos avisos de segurança.\n\nConfirme em:\n{{link}}\n\nO link vale até {{expires_at}} (UTC). Se você não pediu esta confirmação, ignore esta mensagem.",
		Vars: []variable{
			{Key: "display_name", Label: "Nome da pessoa", Type: typeString, Example: "Ana"},
			{Key: "link", Label: "Link de confirmação", Type: typeURL, Example: "https://registry.example/#/verify-email?token=prver_example"},
			{Key: "expires_at", Label: "Validade (UTC)", Type: typeString, Example: "2026-11-13 12:00"},
		},
	},
	{
		ID:      "private-registry-security-notice-v1",
		Key:     TemplateSecurityNotice,
		Name:    "Registry · aviso de segurança",
		Subject: "Aviso de segurança da sua conta",
		HTML:    layoutStart + `<h1 style="margin:0 0 16px;font-size:20px">Aviso de segurança</h1><p style="margin:0 0 8px;line-height:1.5">Olá, {{display_name}}. Registramos esta mudança na sua conta: <strong>{{event_label}}</strong>, em {{occurred_at}} (UTC).</p><p style="margin:16px 0 0;line-height:1.5">Se foi você, nada a fazer. Se não foi, peça a um administrador do registry para recuperar sua conta: {{registry_url}}</p>` + layoutEnd,
		Text:    "Olá, {{display_name}}. Registramos esta mudança na sua conta: {{event_label}}, em {{occurred_at}} (UTC).\n\nSe foi você, nada a fazer. Se não foi, peça a um administrador do registry para recuperar sua conta: {{registry_url}}",
		Vars: []variable{
			{Key: "display_name", Label: "Nome da pessoa", Type: typeString, Example: "Ana"},
			{Key: "event_label", Label: "Mudança registrada", Type: typeString, Example: "nova passkey cadastrada"},
			{Key: "occurred_at", Label: "Quando (UTC)", Type: typeString, Example: "2026-11-12 12:00"},
			{Key: "registry_url", Label: "Endereço do registry", Type: typeURL, Example: "https://registry.example"},
		},
	},
}

var (
	ErrInvalidMessage = errors.New("email message is invalid")
	placeholder       = regexp.MustCompile(`\{\{([a-z_]+)\}\}`)
)

func lookup(template Template) (definition, bool) {
	for _, item := range definitions {
		if item.Key == template {
			return item, true
		}
	}
	return definition{}, false
}

// Message is one email to one recipient. Data holds exactly the template's
// variables.
type Message struct {
	Template Template          `json:"template"`
	To       string            `json:"to"`
	Data     map[string]string `json:"data"`
}

// Validate checks the recipient and that Data matches the template's
// declared variables exactly, with safe values.
func (m Message) Validate() error {
	item, ok := lookup(m.Template)
	if !ok || !validAddress(m.To) || len(m.Data) != len(item.Vars) {
		return ErrInvalidMessage
	}
	for _, v := range item.Vars {
		value, present := m.Data[v.Key]
		if !present || value == "" || len(value) > 2048 {
			return ErrInvalidMessage
		}
		for _, r := range value {
			if unicode.IsControl(r) {
				return ErrInvalidMessage
			}
		}
		if v.Type == typeURL {
			parsed, err := url.Parse(value)
			if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil {
				return ErrInvalidMessage
			}
		}
	}
	return nil
}

func validAddress(value string) bool {
	if len(value) < 3 || len(value) > 254 || strings.ContainsAny(value, "\r\n<>\" ,;") {
		return false
	}
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value && parsed.Name == "" && strings.Count(value, "@") == 1
}

// ValidAddress reports whether value is a plain email address the registry
// accepts as a recipient.
func ValidAddress(value string) bool { return validAddress(value) }

// Rendered is a message ready for providers that do not render templates.
type Rendered struct {
	Subject string
	Text    string
	HTML    string
}

// Render fills the template locally. Values are HTML-escaped in the HTML
// body; validation already rejected control characters, so no value can
// break out of the subject header.
func Render(m Message) (Rendered, error) {
	if err := m.Validate(); err != nil {
		return Rendered{}, err
	}
	item, _ := lookup(m.Template)
	fill := func(source string, escape bool) string {
		return placeholder.ReplaceAllStringFunc(source, func(match string) string {
			value := m.Data[match[2:len(match)-2]]
			if escape {
				return html.EscapeString(value)
			}
			return value
		})
	}
	return Rendered{Subject: fill(item.Subject, false), Text: fill(item.Text, false), HTML: fill(item.HTML, true)}, nil
}

// Templates lists the template keys, for diagnostics and tests.
func Templates() []Template {
	keys := make([]Template, 0, len(definitions))
	for _, item := range definitions {
		keys = append(keys, item.Key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

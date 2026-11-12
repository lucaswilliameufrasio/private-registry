package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// softwareAuthenticator is a minimal platform authenticator: ES256, no
// attestation, resident credential, configurable user verification.
type softwareAuthenticator struct {
	t       *testing.T
	key     *ecdsa.PrivateKey
	id      []byte
	user    []byte
	counter uint32
}

func newSoftwareAuthenticator(t *testing.T) *softwareAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &softwareAuthenticator{t: t, key: key, id: id}
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func (a *softwareAuthenticator) clientData(kind, challenge, origin string) []byte {
	encoded, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return encoded
}

func (a *softwareAuthenticator) authData(flags byte, attested bool) []byte {
	rp := sha256.Sum256([]byte("registry.example"))
	data := append([]byte{}, rp[:]...)
	data = append(data, flags)
	data = binary.BigEndian.AppendUint32(data, a.counter)
	if attested {
		data = append(data, make([]byte, 16)...)
		data = binary.BigEndian.AppendUint16(data, uint16(len(a.id)))
		data = append(data, a.id...)
		x := a.key.PublicKey.X.FillBytes(make([]byte, 32))
		y := a.key.PublicKey.Y.FillBytes(make([]byte, 32))
		cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		if err != nil {
			a.t.Fatal(err)
		}
		data = append(data, cose...)
	}
	return data
}

func (a *softwareAuthenticator) register(options []byte, origin string) []byte {
	a.t.Helper()
	var parsed struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
			AuthenticatorSelection struct {
				UserVerification string `json:"userVerification"`
				ResidentKey      string `json:"residentKey"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &parsed); err != nil {
		a.t.Fatal(err)
	}
	if parsed.PublicKey.AuthenticatorSelection.UserVerification != "required" || parsed.PublicKey.AuthenticatorSelection.ResidentKey != "required" {
		a.t.Fatalf("registration does not demand user verification and a resident key: %s", options)
	}
	user, err := base64.RawURLEncoding.DecodeString(parsed.PublicKey.User.ID)
	if err != nil {
		a.t.Fatal(err)
	}
	a.user = user
	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(0x45, true)})
	if err != nil {
		a.t.Fatal(err)
	}
	response, _ := json.Marshal(map[string]any{"id": b64(a.id), "rawId": b64(a.id), "type": "public-key", "authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{}, "response": map[string]any{"clientDataJSON": b64(a.clientData("webauthn.create", parsed.PublicKey.Challenge, origin)), "attestationObject": b64(attestation), "transports": []string{"internal"}}})
	return response
}

func (a *softwareAuthenticator) assert(options []byte, origin string, flags byte) []byte {
	a.t.Helper()
	var parsed struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			UserVerification string `json:"userVerification"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &parsed); err != nil {
		a.t.Fatal(err)
	}
	if parsed.PublicKey.UserVerification != "required" {
		a.t.Fatalf("login does not demand user verification: %s", options)
	}
	a.counter++
	authData := a.authData(flags, false)
	clientData := a.clientData("webauthn.get", parsed.PublicKey.Challenge, origin)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	response, _ := json.Marshal(map[string]any{"id": b64(a.id), "rawId": b64(a.id), "type": "public-key", "clientExtensionResults": map[string]any{}, "response": map[string]any{"clientDataJSON": b64(clientData), "authenticatorData": b64(authData), "signature": b64(signature), "userHandle": b64(a.user)}})
	return response
}

func TestPasskeysRegisterAndSignInWithoutPassword(t *testing.T) {
	fixture := newAuthHTTPFixture(t)
	member := seedHTTPUser(t, fixture, "passkey.member")
	login := authHTTPRequest(fixture.handler, http.MethodPost, "/api/v1/auth/login", `{"login_name":"passkey.member","password":"synthetic-http-member-password"}`, authTestOrigin, "registry.example")
	session := assertSessionCookies(t, login)
	send := func(cookies map[string]*http.Cookie, path string, body []byte) *httptest.ResponseRecorder {
		csrf := ""
		if cookies[csrfCookieName] != nil {
			csrf = cookies[csrfCookieName].Value
		}
		return authHTTPRequestWithCookies(fixture.handler, http.MethodPost, path, string(body), authTestOrigin, "registry.example", cookies, csrf)
	}
	withCeremony := func(cookies map[string]*http.Cookie, response *httptest.ResponseRecorder) map[string]*http.Cookie {
		merged := map[string]*http.Cookie{}
		for name, cookie := range cookies {
			merged[name] = cookie
		}
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == passkeyCookieName {
				merged[cookie.Name] = cookie
			}
		}
		return merged
	}

	authenticator := newSoftwareAuthenticator(t)
	start := send(session, "/api/v1/auth/passkeys/registration/start", []byte(`{"name":"laptop"}`))
	if start.Code != http.StatusOK {
		t.Fatalf("registration start: %d %s", start.Code, start.Body.String())
	}
	finish := send(withCeremony(session, start), "/api/v1/auth/passkeys/registration/finish", authenticator.register(start.Body.Bytes(), authTestOrigin))
	if finish.Code != http.StatusCreated {
		t.Fatalf("registration finish: %d %s", finish.Code, finish.Body.String())
	}
	// A registration for another origin is refused.
	other := newSoftwareAuthenticator(t)
	start = send(session, "/api/v1/auth/passkeys/registration/start", []byte(`{"name":"phishing"}`))
	if response := send(withCeremony(session, start), "/api/v1/auth/passkeys/registration/finish", other.register(start.Body.Bytes(), "https://evil.example")); response.Code != http.StatusUnauthorized {
		t.Fatalf("registration from another origin: %d", response.Code)
	}

	signIn := func(flags byte, origin string) *httptest.ResponseRecorder {
		begin := send(nil, "/api/v1/auth/passkeys/login/start", nil)
		if begin.Code != http.StatusOK {
			t.Fatalf("login start: %d", begin.Code)
		}
		return send(withCeremony(nil, begin), "/api/v1/auth/passkeys/login/finish", authenticator.assert(begin.Body.Bytes(), origin, flags))
	}
	signedIn := signIn(0x05, authTestOrigin)
	if signedIn.Code != http.StatusOK || !strings.Contains(signedIn.Body.String(), `"authenticated"`) {
		t.Fatalf("passkey login: %d %s", signedIn.Code, signedIn.Body.String())
	}
	passkeySession := assertSessionCookies(t, signedIn)
	if response := authHTTPRequestWithCookies(fixture.handler, http.MethodGet, "/api/v1/auth/passkeys", "", "", "registry.example", passkeySession, ""); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"laptop"`) || strings.Contains(response.Body.String(), "phishing") {
		t.Fatalf("passkey list: %d %s", response.Code, response.Body.String())
	}
	var level string
	if err := fixture.db.QueryRow(`SELECT level FROM registry_auth_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`, member).Scan(&level); err != nil || level != "mfa" {
		t.Fatalf("passkey session level: %q %v", level, err)
	}
	// Presence without user verification does not sign in.
	if response := signIn(0x01, authTestOrigin); response.Code != http.StatusUnauthorized {
		t.Fatalf("login without user verification: %d", response.Code)
	}
	if response := signIn(0x05, "https://evil.example"); response.Code != http.StatusUnauthorized {
		t.Fatalf("login from another origin: %d", response.Code)
	}
	// The same assertion cannot be replayed with the same ceremony.
	begin := send(nil, "/api/v1/auth/passkeys/login/start", nil)
	ceremony := withCeremony(nil, begin)
	assertion := authenticator.assert(begin.Body.Bytes(), authTestOrigin, 0x05)
	if response := send(ceremony, "/api/v1/auth/passkeys/login/finish", assertion); response.Code != http.StatusOK {
		t.Fatalf("login: %d", response.Code)
	}
	if response := send(ceremony, "/api/v1/auth/passkeys/login/finish", assertion); response.Code != http.StatusUnauthorized {
		t.Fatalf("replayed assertion: %d", response.Code)
	}
	// Without the ceremony cookie nothing is accepted.
	begin = send(nil, "/api/v1/auth/passkeys/login/start", nil)
	if response := send(nil, "/api/v1/auth/passkeys/login/finish", authenticator.assert(begin.Body.Bytes(), authTestOrigin, 0x05)); response.Code != http.StatusUnauthorized {
		t.Fatalf("login without the ceremony: %d", response.Code)
	}
	// Deleting the passkey stops it; a suspended account cannot sign in.
	var passkeyID string
	if err := fixture.db.QueryRow(`SELECT credential_id FROM registry_webauthn_credentials WHERE user_id = ?`, member).Scan(&passkeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.db.Exec(`UPDATE registry_users SET status = 'suspended' WHERE user_id = ?`, member); err != nil {
		t.Fatal(err)
	}
	if response := signIn(0x05, authTestOrigin); response.Code != http.StatusUnauthorized {
		t.Fatalf("suspended account signed in: %d", response.Code)
	}
	if _, err := fixture.db.Exec(`UPDATE registry_users SET status = 'active' WHERE user_id = ?`, member); err != nil {
		t.Fatal(err)
	}
	fresh := signIn(0x05, authTestOrigin)
	freshSession := assertSessionCookies(t, fresh)
	if response := authHTTPRequestWithCookies(fixture.handler, http.MethodDelete, "/api/v1/auth/passkeys/"+passkeyID, "", authTestOrigin, "registry.example", freshSession, freshSession[csrfCookieName].Value); response.Code != http.StatusNoContent {
		t.Fatalf("delete passkey: %d %s", response.Code, response.Body.String())
	}
	if response := signIn(0x05, authTestOrigin); response.Code != http.StatusUnauthorized {
		t.Fatalf("deleted passkey signed in: %d", response.Code)
	}
}

package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMuiraVerifierRejectsUntrustedTokens(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": issuer + "/jwks", "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "fixture", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	client := server.Client()
	client.Timeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	verifier, err := newMuiraVerifier(ctx, issuer, "synthetic-client", client)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	sign := func(iss string, aud any, sub, nonce string, expiry time.Time) string {
		t.Helper()
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"fixture","typ":"JWT"}`))
		claims, err := json.Marshal(map[string]any{"iss": iss, "aud": aud, "sub": sub, "nonce": nonce, "exp": expiry.Unix(), "iat": time.Now().Unix()})
		if err != nil {
			t.Fatal(err)
		}
		body := header + "." + base64.RawURLEncoding.EncodeToString(claims)
		digest := sha256.Sum256([]byte(body))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return body + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	now := time.Now()
	valid := sign(issuer, "synthetic-client", subject.String(), "synthetic-nonce", now.Add(time.Minute))
	if got, err := verifier.verify(ctx, valid, "synthetic-nonce"); err != nil || got != subject.String() {
		t.Fatalf("valid synthetic token rejected: %v", err)
	}
	parts := strings.Split(valid, ".")
	if len(parts) != 3 {
		t.Fatal("synthetic token format invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	signature[0] ^= 1
	badSignature := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature)
	for _, item := range []struct {
		name  string
		token string
		nonce string
	}{
		{"wrong nonce", valid, "wrong"},
		{"wrong audience", sign(issuer, "other-client", subject.String(), "synthetic-nonce", now.Add(time.Minute)), "synthetic-nonce"},
		{"multiple audiences", sign(issuer, []string{"synthetic-client", "other-client"}, subject.String(), "synthetic-nonce", now.Add(time.Minute)), "synthetic-nonce"},
		{"wrong issuer", sign("https://other.example", "synthetic-client", subject.String(), "synthetic-nonce", now.Add(time.Minute)), "synthetic-nonce"},
		{"expired", sign(issuer, "synthetic-client", subject.String(), "synthetic-nonce", now.Add(-time.Hour)), "synthetic-nonce"},
		{"invalid subject", sign(issuer, "synthetic-client", "person@example.invalid", "synthetic-nonce", now.Add(time.Minute)), "synthetic-nonce"},
		{"bad signature", badSignature, "synthetic-nonce"},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := verifier.verify(ctx, item.token, item.nonce); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
	if _, err := verifier.verify(context.Background(), valid, "synthetic-nonce"); err == nil {
		t.Fatal("verification without deadline accepted")
	}
	if _, err := newMuiraVerifier(ctx, fmt.Sprintf("http://%s", server.Listener.Addr()), "synthetic-client", client); err == nil {
		t.Fatal("plaintext issuer accepted")
	}
}

// Package testhydra holds helpers shared by the acceptance tests and the
// empirical checks that run against the local Hydra from compose.yaml.
package testhydra

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// AdminURL is the Hydra Admin API (HYDRA_ADMIN_URL, default http://127.0.0.1:4445).
func AdminURL() string {
	if v := os.Getenv("HYDRA_ADMIN_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://127.0.0.1:4445"
}

// PublicURL is the Hydra public API (HYDRA_PUBLIC_URL, default http://127.0.0.1:4444).
func PublicURL() string {
	if v := os.Getenv("HYDRA_PUBLIC_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://127.0.0.1:4444"
}

// TokenAudience is the token endpoint URL as Hydra knows it (issuer from
// testdata/hydra/hydra.yml + /oauth2/token); jwt-bearer assertions must use it as aud.
const TokenAudience = "http://localhost:4444/oauth2/token"

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Do performs a JSON request and returns status and body.
func Do(t testing.TB, method, u string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, u, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// Admin is Do against the Admin API path p.
func Admin(t testing.TB, method, p string, body any) (int, []byte) {
	t.Helper()
	return Do(t, method, AdminURL()+p, body)
}

// TokenResult is the outcome of a token request.
type TokenResult struct {
	Status      int
	AccessToken string
	ExpiresIn   int
	Scope       string
	Error       string
	Description string
}

// OK reports whether a token was issued.
func (r TokenResult) OK() bool { return r.Status == http.StatusOK && r.AccessToken != "" }

func (r TokenResult) String() string {
	if r.OK() {
		return fmt.Sprintf("200 token (expires_in=%d, scope=%q)", r.ExpiresIn, r.Scope)
	}
	return fmt.Sprintf("%d %s: %s", r.Status, r.Error, r.Description)
}

// Token posts form to the public token endpoint, optionally with basic auth.
func Token(t testing.TB, form url.Values, basicUser, basicPass string) TokenResult {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, PublicURL()+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicUser != "" {
		req.SetBasicAuth(url.QueryEscape(basicUser), url.QueryEscape(basicPass))
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	return TokenResult{Status: resp.StatusCode, AccessToken: out.AccessToken, ExpiresIn: out.ExpiresIn, Scope: out.Scope, Error: out.Error, Description: out.Description}
}

// ClientCredentials requests a client_credentials token with client_secret_basic.
func ClientCredentials(t testing.TB, clientID, secret, scope string) TokenResult {
	t.Helper()
	f := url.Values{"grant_type": {"client_credentials"}}
	if scope != "" {
		f.Set("scope", scope)
	}
	return Token(t, f, clientID, secret)
}

// Key is a test signing key acting as an external JWT issuer (e.g. Forgejo).
type Key struct {
	Private *rsa.PrivateKey
	Kid     string
}

// NewKey generates a fresh RSA-2048 key with the given kid.
func NewKey(t testing.TB, kid string) *Key {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &Key{Private: k, Kid: kid}
}

// PublicJWK returns the public JWK JSON (kty, kid, alg, use, n, e).
func (k *Key) PublicJWK(t testing.TB) string {
	t.Helper()
	j := jose.JSONWebKey{Key: &k.Private.PublicKey, KeyID: k.Kid, Algorithm: "RS256", Use: "sig"}
	b, err := j.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Assertion signs a JWT for the jwt-bearer grant. kidHeader=false omits the
// "kid" JOSE header (Hydra then searches all keys of issuer+subject).
func (k *Key) Assertion(t testing.TB, iss, sub string, ttl time.Duration, kidHeader bool) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kidHeader {
		opts = opts.WithHeader("kid", k.Kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k.Private}, opts)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := jwt.Claims{
		Issuer:   iss,
		Subject:  sub,
		Audience: jwt.Audience{TokenAudience},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(ttl)),
		// no jti: oauth2.grant.jwt.jti_optional = true
	}
	s, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// JWTBearer requests a token with the jwt-bearer grant. For a public client
// (token_endpoint_auth_method=none) clientSecret is "" and client_id is sent
// in the form body.
func JWTBearer(t testing.TB, clientID, clientSecret, assertion, scope string) TokenResult {
	t.Helper()
	f := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	if scope != "" {
		f.Set("scope", scope)
	}
	if clientSecret == "" {
		f.Set("client_id", clientID)
		return Token(t, f, "", "")
	}
	return Token(t, f, clientID, clientSecret)
}

// CreateTrust creates a trust directly through the Admin API (bypassing the
// provider and its validators) and returns its id.
func CreateTrust(t testing.TB, iss, sub string, scope []string, jwk string, expiresAt time.Time) (string, int, []byte) {
	t.Helper()
	body := map[string]any{
		"issuer":     iss,
		"scope":      scope,
		"jwk":        json.RawMessage(jwk),
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	}
	if sub == "" {
		body["allow_any_subject"] = true
	} else {
		body["subject"] = sub
	}
	st, b := Admin(t, http.MethodPost, "/admin/trust/grants/jwt-bearer/issuers", body)
	var out struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &out)
	return out.ID, st, b
}

// Ready skips the test when the local Hydra is not reachable.
func Ready(t testing.TB) {
	t.Helper()
	resp, err := httpClient.Get(AdminURL() + "/health/ready")
	if err != nil && os.Getenv("TF_ACC") != "" {
		t.Fatalf("TF_ACC is set but local Hydra is not reachable at %s (start it with `podman compose up -d --wait`): %v", AdminURL(), err)
	}
	if err != nil {
		t.Skipf("local Hydra not reachable at %s (start it with `podman compose up -d --wait`): %v", AdminURL(), err)
	}
	resp.Body.Close()
}

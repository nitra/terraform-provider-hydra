package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	fwprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	fwresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	hydra "github.com/ory/hydra-client-go/v2"
)

func TestSchemasAreValid(t *testing.T) {
	ctx := context.Background()
	p := New("test")()
	var presp fwprovider.SchemaResponse
	p.Schema(ctx, fwprovider.SchemaRequest{}, &presp)
	if presp.Diagnostics.HasError() {
		t.Fatal(presp.Diagnostics)
	}
	for _, f := range p.Resources(ctx) {
		r := f()
		var resp fwresource.SchemaResponse
		r.Schema(ctx, fwresource.SchemaRequest{}, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatal(resp.Diagnostics)
		}
		if d := resp.Schema.ValidateImplementation(ctx); d.HasError() {
			t.Fatal(d)
		}
	}
}

func TestOAuth2ClientSchemaCoversAllLifespans(t *testing.T) {
	var resp fwresource.SchemaResponse
	NewOAuth2ClientResource().Schema(context.Background(), fwresource.SchemaRequest{}, &resp)
	if len(lifespanKeys) != 13 {
		t.Fatalf("expected 13 lifespans, got %d", len(lifespanKeys))
	}
	m := oauth2ClientModel{}
	if len(m.lifespans()) != 13 {
		t.Fatalf("model maps %d lifespans", len(m.lifespans()))
	}
	for _, k := range lifespanKeys {
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("schema misses %s", k)
		}
		if _, ok := m.lifespans()[k]; !ok {
			t.Errorf("model misses %s", k)
		}
	}
	// every field of the generated model (except read-only / DCR ones) is exposed
	skip := map[string]bool{"client_secret": true, "client_secret_expires_at": true, "registration_access_token": true, "registration_client_uri": true}
	for _, k := range oauth2ClientAPIFields() {
		if skip[k] {
			continue
		}
		if _, ok := resp.Schema.Attributes[k]; !ok {
			t.Errorf("OAuth2Client field %q is not in the schema", k)
		}
	}
}

// oauth2ClientAPIFields lists the JSON keys of the generated OAuth2Client.
func oauth2ClientAPIFields() []string {
	s := "x"
	b := true
	var i int64
	now := time.Now()
	c := hydra.OAuth2Client{
		AccessTokenStrategy: &s, AllowedCorsOrigins: []string{s}, Audience: []string{s},
		BackchannelLogoutSessionRequired: &b, BackchannelLogoutUri: &s, ClientId: &s, ClientName: &s,
		ClientSecret: &s, ClientSecretExpiresAt: &i, ClientUri: &s, Contacts: []string{s}, CreatedAt: &now,
		FrontchannelLogoutSessionRequired: &b, FrontchannelLogoutUri: &s, GrantTypes: []string{s},
		Jwks: &hydra.JsonWebKeySet{}, JwksUri: &s, LogoUri: &s, Metadata: map[string]any{}, Owner: &s,
		PolicyUri: &s, PostLogoutRedirectUris: []string{s}, RedirectUris: []string{s},
		RegistrationAccessToken: &s, RegistrationClientUri: &s, RequestObjectSigningAlg: &s,
		RequestUris: []string{s}, ResponseTypes: []string{s}, Scope: &s, SectorIdentifierUri: &s,
		SkipConsent: &b, SkipLogoutConsent: &b, SubjectType: &s, TokenEndpointAuthMethod: &s,
		TokenEndpointAuthSigningAlg: &s, TosUri: &s, UpdatedAt: &now, UserinfoSignedResponseAlg: &s,
	}
	m, _ := c.ToMap()
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestDurationsEqual(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		eq   bool
	}{
		{"10m", "10m0s", true},
		{"1h", "60m", true},
		{"720h", "720h0m0s", true},
		{"10m", "11m", false},
		{"bad", "10m", false},
	} {
		if got := durationsEqual(tc.a, tc.b); got != tc.eq {
			t.Errorf("durationsEqual(%q,%q)=%v", tc.a, tc.b, got)
		}
	}
	if !hydraDurationRe.MatchString("1h30m") || hydraDurationRe.MatchString("1.5h") || hydraDurationRe.MatchString("-1h") || hydraDurationRe.MatchString("") {
		t.Error("hydraDurationRe mismatch")
	}
	eq, _ := NewDurationValue("10m").StringSemanticEquals(context.Background(), NewDurationValue("10m0s"))
	if !eq {
		t.Error("semantic equality")
	}
}

func TestTimestampsEqual(t *testing.T) {
	if !timestampsEqual("2036-01-01T03:00:00+03:00", "2036-01-01T00:00:00Z") {
		t.Error("zones")
	}
	if !timestampsEqual("2036-01-01T00:00:00.2Z", "2036-01-01T00:00:00Z") {
		t.Error("sub-second rounding")
	}
	if timestampsEqual("2036-01-01T00:00:01Z", "2036-01-01T00:00:00Z") {
		t.Error("different seconds")
	}
}

func TestJSONEqual(t *testing.T) {
	if !jsonEqual(`{"a":1,"b":[1,2]}`, `{ "b": [1,2], "a": 1 }`) || jsonEqual(`{"a":1}`, `{"a":2}`) {
		t.Error("jsonEqual")
	}
}

func TestParsePublicJWK(t *testing.T) {
	ok := `{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB","x5t":"zz"}`
	if _, err := parsePublicJWK(ok); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"private": `{"kty":"RSA","kid":"k1","n":"abc","e":"AQAB","d":"x"}`,
		"oct":     `{"kty":"oct","kid":"k1","k":"x"}`,
		"no kid":  `{"kty":"RSA","n":"abc","e":"AQAB"}`,
		"set":     `{"keys":[]}`,
		"json":    `nope`,
	} {
		if _, err := parsePublicJWK(bad); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if jwkKid(ok) != "k1" {
		t.Error("kid")
	}
	if jwkPublicMaterial(ok) != jwkPublicMaterial(`{"e":"AQAB","n":"abc","kid":"k1","kty":"RSA"}`) {
		t.Error("material should ignore order / non-key members")
	}
	if jwkPublicMaterial(ok) == jwkPublicMaterial(`{"kty":"RSA","kid":"k1","n":"abd","e":"AQAB"}`) {
		t.Error("material should differ")
	}
}

func runStringValidator(v validator.String, s types.String) bool {
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{Path: path.Root("x"), ConfigValue: s}, resp)
	return !resp.Diagnostics.HasError()
}

func TestFutureTimestampValidator(t *testing.T) {
	now := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	v := futureTimestampValidator{now: now}
	if !runStringValidator(v, types.StringValue("2036-01-01T00:00:00Z")) {
		t.Error("future rejected")
	}
	if runStringValidator(v, types.StringValue("2025-01-01T00:00:00Z")) {
		t.Error("past accepted")
	}
	if !runStringValidator(v, types.StringUnknown()) {
		t.Error("unknown must pass")
	}
}

func TestJWKSValidator(t *testing.T) {
	good := `{"keys":[{"kty":"RSA","kid":"a","alg":"RS256","use":"sig","n":"x","e":"AQAB"}]}`
	if !runStringValidator(jwksValidator{}, types.StringValue(good)) {
		t.Error("good jwks rejected")
	}
	for _, bad := range []string{
		`{"keys":[{"kty":"RSA","kid":"a","alg":"RS256","use":"sig","n":"x","e":"AQAB","d":"p"}]}`,
		`{"keys":[{"kty":"RSA","kid":"a","n":"x","e":"AQAB"}]}`,
		`{"keys":[{"kty":"RSA","kid":"a","alg":"RS256","use":"sig","n":"x","e":"AQAB","x5t":"t"}]}`,
	} {
		if runStringValidator(jwksValidator{}, types.StringValue(bad)) {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestGrantTypesValidatorOnlyWarns(t *testing.T) {
	l := types.ListValueMust(types.StringType, []attr.Value{
		types.StringValue("urn:ietf:params:oauth:grant-type:jwt-bearer"),
		types.StringValue("urn:ietf:params:oauth:grant-type:device_code"),
		types.StringValue("custom"),
	})
	resp := &validator.ListResponse{}
	grantTypesValidator{}.ValidateList(context.Background(), validator.ListRequest{Path: path.Root("grant_types"), ConfigValue: l}, resp)
	if resp.Diagnostics.HasError() || resp.Diagnostics.WarningsCount() != 1 {
		t.Fatalf("expected exactly one warning, got %v", resp.Diagnostics)
	}
}

func TestToAPIFromAPIRoundTrip(t *testing.T) {
	m := oauth2ClientModel{
		ClientID:                          types.StringValue("c1"),
		ClientName:                        types.StringValue(""),
		GrantTypes:                        types.ListValueMust(types.StringType, []attr.Value{types.StringValue("client_credentials")}),
		RedirectURIs:                      types.ListValueMust(types.StringType, []attr.Value{}),
		Metadata:                          jsontypes.NewNormalizedValue(`{"a":1}`),
		Jwks:                              jsontypes.NewNormalizedNull(),
		Scope:                             types.StringUnknown(),
		JwtBearerGrantAccessTokenLifespan: NewDurationValue("10m"),
	}
	for k, v := range m.lifespans() {
		if k != "jwt_bearer_grant_access_token_lifespan" {
			*v = NewDurationNull()
		}
	}
	c, d := m.toAPI()
	if d.HasError() {
		t.Fatal(d)
	}
	if c.GetJwtBearerGrantAccessTokenLifespan() != "10m" || c.Scope != nil || c.GetClientName() != "" {
		t.Fatalf("toAPI: %+v", c)
	}
	if c.ClientSecret != nil {
		t.Fatal("secret must not be set by toAPI")
	}

	// server echo with canonical duration and defaults
	c.JwtBearerGrantAccessTokenLifespan = hydra.PtrString("10m0s")
	c.Scope = hydra.PtrString("offline_access offline openid")
	c.ClientSecret = hydra.PtrString("must-not-leak")
	c.RedirectUris = []string{}
	if d := m.fromAPI(c); d.HasError() {
		t.Fatal(d)
	}
	if m.JwtBearerGrantAccessTokenLifespan.ValueString() != "10m" {
		t.Errorf("configured spelling not kept: %s", m.JwtBearerGrantAccessTokenLifespan)
	}
	if !m.ClientSecretWO.IsNull() {
		t.Error("write-only must be null")
	}
	if m.ClientName.IsNull() || m.ClientName.ValueString() != "" {
		t.Error("explicit empty string should be kept")
	}
	if m.RedirectURIs.IsNull() {
		t.Error("explicit empty list should be kept")
	}
	if m.Owner.IsNull() == false {
		t.Error("absent owner should be null")
	}
	if m.Scope.ValueString() != "offline_access offline openid" {
		t.Error("server default scope")
	}
	if strings.TrimSpace(m.Metadata.ValueString()) != `{"a":1}` {
		t.Errorf("metadata %s", m.Metadata)
	}
}

func TestNextPageToken(t *testing.T) {
	h := http.Header{}
	h.Add("Link", `<http://h/admin/trust/grants/jwt-bearer/issuers?page_size=2&page_token=abc>; rel="next", <http://h/x?page_token=first>; rel="first"`)
	if got := nextPageToken(&http.Response{Header: h}); got != "abc" {
		t.Fatalf("got %q", got)
	}
	if nextPageToken(&http.Response{Header: http.Header{}}) != "" || nextPageToken(nil) != "" {
		t.Fatal("expected empty")
	}
}

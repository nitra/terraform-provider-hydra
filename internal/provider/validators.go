package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// knownGrantTypes are the grant types Hydra v26.2.0 implements. Hydra itself
// does not validate grant_types on the client, so the provider only warns
// about unknown values instead of rejecting them (no hard whitelist).
var knownGrantTypes = []string{
	"authorization_code",
	"implicit",
	"refresh_token",
	"client_credentials",
	"password",
	"urn:ietf:params:oauth:grant-type:jwt-bearer",
	"urn:ietf:params:oauth:grant-type:device_code",
	"urn:ietf:params:oauth:grant-type:token-exchange",
}

type grantTypesValidator struct{}

func (grantTypesValidator) Description(context.Context) string {
	return "warns about grant types unknown to Hydra v26.2.0"
}

func (v grantTypesValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (grantTypesValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	var items []types.String
	resp.Diagnostics.Append(req.ConfigValue.ElementsAs(ctx, &items, false)...)
	for _, it := range items {
		if it.IsUnknown() || it.IsNull() {
			continue
		}
		if !slices.Contains(knownGrantTypes, it.ValueString()) {
			resp.Diagnostics.AddAttributeWarning(req.Path, "Unknown grant type",
				fmt.Sprintf("%q is not a grant type known to Hydra v26.2.0 (%s). It is sent as-is.",
					it.ValueString(), strings.Join(knownGrantTypes, ", ")))
		}
	}
}

// privateJWKMembers are JWK members that only exist on private / symmetric
// keys (RFC 7518 §6). A trust relationship must only ever carry a public key.
var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// parsePublicJWK parses s as a single public JWK and returns its members.
func parsePublicJWK(s string) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	if _, isSet := m["keys"]; isSet {
		return nil, fmt.Errorf("expected a single JWK, got a JWK Set (pick one element of \"keys\")")
	}
	kty, _ := m["kty"].(string)
	if kty == "" {
		return nil, fmt.Errorf("missing \"kty\"")
	}
	if kid, _ := m["kid"].(string); kid == "" {
		return nil, fmt.Errorf("missing \"kid\" (Hydra requires a key ID)")
	}
	for _, f := range privateJWKMembers {
		if _, ok := m[f]; ok {
			return nil, fmt.Errorf("contains private/symmetric key member %q - only public keys may be trusted", f)
		}
	}
	return m, nil
}

// jwkKid returns the "kid" of a JWK JSON string, or "".
func jwkKid(s string) string {
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return ""
	}
	kid, _ := m["kid"].(string)
	return kid
}

// jwkPublicMaterial returns a canonical string of the members that define the
// public key itself (used to detect key rotation that kept the same kid).
func jwkPublicMaterial(s string) string {
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return ""
	}
	parts := []string{}
	for _, f := range []string{"kty", "crv", "n", "e", "x", "y"} {
		if v, ok := m[f].(string); ok {
			parts = append(parts, f+"="+v)
		}
	}
	return strings.Join(parts, ";")
}

type publicJWKValidator struct{}

func (publicJWKValidator) Description(context.Context) string {
	return "must be a single public JWK (no private members) with a kid"
}

func (v publicJWKValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (publicJWKValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, err := parsePublicJWK(req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid JWK", err.Error())
	}
}

type jwksValidator struct{}

func (jwksValidator) Description(context.Context) string {
	return "must be a JWK Set ({\"keys\": [...]}) of public keys"
}

func (v jwksValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (jwksValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal([]byte(req.ConfigValue.ValueString()), &set); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid JWKS", err.Error())
		return
	}
	for i, k := range set.Keys {
		for _, f := range privateJWKMembers {
			if _, ok := k[f]; ok {
				resp.Diagnostics.AddAttributeError(req.Path, "Invalid JWKS",
					fmt.Sprintf("keys[%d] contains private/symmetric member %q - a client JWKS must only hold public keys (it is stored in state)", i, f))
			}
		}
		// The generated Hydra client (JsonWebKey) decodes keys strictly:
		// alg/kid/kty/use are required and unknown members are rejected, so
		// a key that violates this would make every later read fail.
		for _, f := range []string{"alg", "kid", "kty", "use"} {
			if s, _ := k[f].(string); s == "" {
				resp.Diagnostics.AddAttributeError(req.Path, "Invalid JWKS",
					fmt.Sprintf("keys[%d] is missing required member %q (prefer jwks_uri for third-party key sets)", i, f))
			}
		}
		for f := range k {
			if !slices.Contains(clientJWKMembers, f) {
				resp.Diagnostics.AddAttributeError(req.Path, "Invalid JWKS",
					fmt.Sprintf("keys[%d] has member %q which Hydra's client model does not support (allowed: %s)", i, f, strings.Join(clientJWKMembers, ", ")))
			}
		}
	}
}

// clientJWKMembers are the public JWK members the generated JsonWebKey model accepts.
var clientJWKMembers = []string{"alg", "crv", "e", "kid", "kty", "n", "use", "x", "x5c", "y"}

// futureTimestampValidator requires a Timestamp in the future (at plan time).
type futureTimestampValidator struct {
	now func() time.Time
}

func (futureTimestampValidator) Description(context.Context) string { return "must be in the future" }

func (v futureTimestampValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v futureTimestampValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	t, err := time.Parse(time.RFC3339Nano, req.ConfigValue.ValueString())
	if err != nil {
		return // reported by the type validation
	}
	now := time.Now
	if v.now != nil {
		now = v.now
	}
	if !t.After(now()) {
		resp.Diagnostics.AddAttributeError(req.Path, "Expiry in the past",
			fmt.Sprintf("%s is not in the future.", req.ConfigValue.ValueString()))
	}
}

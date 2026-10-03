package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	hydra "github.com/ory/hydra-client-go/v2"
)

const trustPath = "/admin/trust/grants/jwt-bearer/issuers"

var (
	_ resource.Resource                   = (*trustResource)(nil)
	_ resource.ResourceWithConfigure      = (*trustResource)(nil)
	_ resource.ResourceWithImportState    = (*trustResource)(nil)
	_ resource.ResourceWithValidateConfig = (*trustResource)(nil)
)

// NewTrustedJWTGrantIssuerResource is the hydra_trusted_jwt_grant_issuer factory.
func NewTrustedJWTGrantIssuerResource() resource.Resource { return &trustResource{} }

type trustResource struct{ c *apiClient }

type trustModel struct {
	ID              types.String `tfsdk:"id"`
	Issuer          types.String `tfsdk:"issuer"`
	Subject         types.String `tfsdk:"subject"`
	AllowAnySubject types.Bool   `tfsdk:"allow_any_subject"`
	Scope           types.Set    `tfsdk:"scope"`
	JWK             types.String `tfsdk:"jwk"`
	Kid             types.String `tfsdk:"kid"`
	ExpiresAt       Timestamp    `tfsdk:"expires_at"`
	CreatedAt       types.String `tfsdk:"created_at"`
}

func (r *trustResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_trusted_jwt_grant_issuer"
}

func (r *trustResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.c = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *trustResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Trust relationship for the RFC 7523 JWT Bearer grant " +
			"(`urn:ietf:params:oauth:grant-type:jwt-bearer`): Hydra accepts assertions signed by `jwk` " +
			"from `issuer` for `subject` and grants at most `scope`. The Admin API only supports create, get and delete, " +
			"so every change replaces the trust (except re-formatting of `jwk` with the same key).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true, MarkdownDescription: "Trust UUID assigned by Hydra. Import ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"issuer": schema.StringAttribute{
				Required: true, MarkdownDescription: "Value of the `iss` claim of accepted assertions.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"subject": schema.StringAttribute{
				Optional: true, MarkdownDescription: "Value of the `sub` claim of accepted assertions. Exactly one of `subject` / `allow_any_subject = true` is required.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"allow_any_subject": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(false),
				MarkdownDescription: "Accept any `sub`. Conflicts with `subject`.",
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
			},
			"scope": schema.SetAttribute{
				ElementType: types.StringType, Required: true,
				MarkdownDescription: "Scopes the issuer may request.",
				PlanModifiers:       []planmodifier.Set{setplanmodifier.RequiresReplace()},
			},
			"jwk": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "Public JWK (single key, JSON string) that signs the assertions; must contain `kid` and no private members. " +
					"Hydra does not return it, so after `import` it is taken from configuration; " +
					"the trust is replaced when the `kid` or the key material changes.",
				Validators:    []validator.String{publicJWKValidator{}},
				PlanModifiers: []planmodifier.String{jwkReplace{}},
			},
			"kid": schema.StringAttribute{
				Computed: true, MarkdownDescription: "Key ID taken from `jwk`.",
				PlanModifiers: []planmodifier.String{kidFromJWK{}},
			},
			"expires_at": schema.StringAttribute{
				CustomType: TimestampType{}, Optional: true, Computed: true,
				MarkdownDescription: "Expiry (RFC 3339; required, must be in the future). Compared as an instant rounded to seconds, so the zone/format may differ from what Hydra returns (UTC).",
				Validators:          []validator.String{requiredValue{}, futureTimestampValidator{}},
				PlanModifiers:       []planmodifier.String{timestampSemantic(), stringplanmodifier.RequiresReplace()},
			},
			"created_at": schema.StringAttribute{
				Computed: true, MarkdownDescription: "Creation timestamp.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *trustResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var subject types.String
	var anySub types.Bool
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("subject"), &subject)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("allow_any_subject"), &anySub)...)
	if subject.IsUnknown() || anySub.IsUnknown() {
		return
	}
	hasSub := !subject.IsNull() && subject.ValueString() != ""
	anyTrue := !anySub.IsNull() && anySub.ValueBool()
	switch {
	case hasSub && anyTrue:
		resp.Diagnostics.AddAttributeError(path.Root("allow_any_subject"), "Conflicting attributes",
			"`subject` and `allow_any_subject = true` cannot be used together.")
	case !hasSub && !anyTrue:
		resp.Diagnostics.AddAttributeError(path.Root("subject"), "Missing subject",
			"Set `subject` or `allow_any_subject = true`.")
	}
}

func (r *trustResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan trustModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	exp, err := plan.ExpiresAt.Time()
	if err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("expires_at"), "Invalid expires_at", err.Error())
		return
	}
	var scope []string
	resp.Diagnostics.Append(plan.Scope.ElementsAs(ctx, &scope, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := map[string]any{
		"issuer":            plan.Issuer.ValueString(),
		"allow_any_subject": plan.AllowAnySubject.ValueBool(),
		"scope":             scope,
		"jwk":               json.RawMessage(plan.JWK.ValueString()),
		"expires_at":        exp,
	}
	if !plan.Subject.IsNull() {
		body["subject"] = plan.Subject.ValueString()
	}

	var got hydra.TrustedOAuth2JwtGrantIssuer
	if _, err := r.c.rawJSON(ctx, http.MethodPost, trustPath, body, &got); err != nil {
		resp.Diagnostics.AddError("Creating trusted JWT grant issuer failed", err.Error())
		return
	}
	plan.applyAPI(&got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *trustResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state trustModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var got *hydra.TrustedOAuth2JwtGrantIssuer
	hr, err := r.c.do(ctx, func() (*http.Response, error) {
		var hr *http.Response
		var err error
		got, hr, err = r.c.hydra.OAuth2API.GetTrustedOAuth2JwtGrantIssuer(ctx, state.ID.ValueString()).Execute()
		return hr, err
	})
	if err != nil && statusOf(hr) == http.StatusNotFound {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		addAPIError(&resp.Diagnostics, "Reading trusted JWT grant issuer failed", err)
		return
	}
	state.applyAPI(got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is only reached when `jwk` changed textually but describes the same
// key (see jwkReplace); there is no update API, so only state changes.
func (r *trustResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state trustModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.JWK = plan.JWK
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *trustResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state trustModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	hr, err := r.c.do(ctx, func() (*http.Response, error) {
		return r.c.hydra.OAuth2API.DeleteTrustedOAuth2JwtGrantIssuer(ctx, state.ID.ValueString()).Execute()
	})
	if err != nil && statusOf(hr) != http.StatusNotFound {
		addAPIError(&resp.Diagnostics, "Deleting trusted JWT grant issuer failed", err)
	}
}

func (r *trustResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (m *trustModel) applyAPI(g *hydra.TrustedOAuth2JwtGrantIssuer) {
	m.ID = types.StringValue(g.GetId())
	m.Issuer = types.StringValue(g.GetIssuer())
	if s := g.GetSubject(); s != "" {
		m.Subject = types.StringValue(s)
	} else {
		m.Subject = types.StringNull()
	}
	m.AllowAnySubject = types.BoolValue(g.GetAllowAnySubject())
	scope := g.GetScope()
	slices.Sort(scope)
	elems := make([]attr.Value, len(scope))
	for i, s := range scope {
		elems[i] = types.StringValue(s)
	}
	m.Scope = types.SetValueMust(types.StringType, elems)
	if pk, ok := g.GetPublicKeyOk(); ok && pk.GetKid() != "" {
		m.Kid = types.StringValue(pk.GetKid())
	}
	if g.ExpiresAt != nil {
		nv := NewTimestampValue(*g.ExpiresAt)
		if m.ExpiresAt.IsNull() || m.ExpiresAt.IsUnknown() || !timestampsEqual(m.ExpiresAt.ValueString(), nv.ValueString()) {
			m.ExpiresAt = nv
		}
	}
	if g.CreatedAt != nil {
		m.CreatedAt = NewTimestampValue(*g.CreatedAt).StringValue
	} else if m.CreatedAt.IsUnknown() {
		m.CreatedAt = types.StringNull()
	}
	if m.JWK.IsUnknown() {
		m.JWK = types.StringNull()
	}
}

// ---------------------------------------------------------------------------
// plan modifiers / validators specific to the trust resource
// ---------------------------------------------------------------------------

// kidFromJWK plans `kid` from the configured `jwk`.
type kidFromJWK struct{}

func (kidFromJWK) Description(context.Context) string { return "kid is derived from jwk" }

func (m kidFromJWK) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (kidFromJWK) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	var jwk types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("jwk"), &jwk)...)
	if jwk.IsNull() || jwk.IsUnknown() {
		return
	}
	if kid := jwkKid(jwk.ValueString()); kid != "" {
		resp.PlanValue = types.StringValue(kid)
	}
}

// jwkReplace requires replacement when the key identity changes: a different
// kid (compared with the kid Hydra reports, which also works right after
// import when `jwk` is null in state) or different public key material for the
// same kid (only detectable when the previous jwk is known in state).
// A JWK that is only re-formatted is updated in state without replacement.
type jwkReplace struct{}

func (jwkReplace) Description(context.Context) string {
	return "replaces the trust when the key (kid or key material) changes"
}

func (m jwkReplace) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (jwkReplace) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() || req.ConfigValue.IsUnknown() || req.ConfigValue.IsNull() {
		return
	}
	var stateKid types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("kid"), &stateKid)...)
	newKid := jwkKid(req.ConfigValue.ValueString())
	if !stateKid.IsNull() && !stateKid.IsUnknown() && stateKid.ValueString() != newKid {
		resp.RequiresReplace = true
		return
	}
	if !req.StateValue.IsNull() && !req.StateValue.IsUnknown() &&
		jwkPublicMaterial(req.StateValue.ValueString()) != jwkPublicMaterial(req.ConfigValue.ValueString()) {
		resp.RequiresReplace = true
	}
}

// requiredValue makes an Optional+Computed attribute mandatory in config.
type requiredValue struct{}

func (requiredValue) Description(context.Context) string { return "value is required" }

func (v requiredValue) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (requiredValue) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() {
		resp.Diagnostics.AddAttributeError(req.Path, "Missing required argument",
			fmt.Sprintf("The argument %q is required.", req.Path))
	}
}

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	hydra "github.com/ory/hydra-client-go/v2"
)

var (
	_ resource.Resource                = (*oauth2ClientResource)(nil)
	_ resource.ResourceWithConfigure   = (*oauth2ClientResource)(nil)
	_ resource.ResourceWithImportState = (*oauth2ClientResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*oauth2ClientResource)(nil)
)

// NewOAuth2ClientResource is the hydra_oauth2_client resource factory.
func NewOAuth2ClientResource() resource.Resource { return &oauth2ClientResource{} }

type oauth2ClientResource struct{ c *apiClient }

// lifespanKeys are the 13 per-client token lifespans of Hydra v26.2.0, in the
// order of the OAuth2ClientTokenLifespans model.
var lifespanKeys = []string{
	"authorization_code_grant_access_token_lifespan",
	"authorization_code_grant_id_token_lifespan",
	"authorization_code_grant_refresh_token_lifespan",
	"client_credentials_grant_access_token_lifespan",
	"device_authorization_grant_access_token_lifespan",
	"device_authorization_grant_id_token_lifespan",
	"device_authorization_grant_refresh_token_lifespan",
	"implicit_grant_access_token_lifespan",
	"implicit_grant_id_token_lifespan",
	"jwt_bearer_grant_access_token_lifespan",
	"refresh_token_grant_access_token_lifespan",
	"refresh_token_grant_id_token_lifespan",
	"refresh_token_grant_refresh_token_lifespan",
}

// secretAuthMethods are token endpoint auth methods that authenticate with
// the client secret. Creating such a client without client_secret_wo would
// make Hydra generate a secret that the provider never stores.
var secretAuthMethods = []string{"client_secret_basic", "client_secret_post", "client_secret_jwt"}

type oauth2ClientModel struct {
	ID       types.String `tfsdk:"id"`
	ClientID types.String `tfsdk:"client_id"`

	ClientSecretWO        types.String `tfsdk:"client_secret_wo"`
	ClientSecretWOVersion types.Int64  `tfsdk:"client_secret_wo_version"`

	ClientName types.String `tfsdk:"client_name"`
	Owner      types.String `tfsdk:"owner"`
	ClientURI  types.String `tfsdk:"client_uri"`
	LogoURI    types.String `tfsdk:"logo_uri"`
	PolicyURI  types.String `tfsdk:"policy_uri"`
	TosURI     types.String `tfsdk:"tos_uri"`
	Contacts   types.List   `tfsdk:"contacts"`

	GrantTypes             types.List   `tfsdk:"grant_types"`
	ResponseTypes          types.List   `tfsdk:"response_types"`
	Scope                  types.String `tfsdk:"scope"`
	Audience               types.List   `tfsdk:"audience"`
	RedirectURIs           types.List   `tfsdk:"redirect_uris"`
	PostLogoutRedirectURIs types.List   `tfsdk:"post_logout_redirect_uris"`
	AllowedCORSOrigins     types.List   `tfsdk:"allowed_cors_origins"`
	RequestURIs            types.List   `tfsdk:"request_uris"`

	TokenEndpointAuthMethod     types.String         `tfsdk:"token_endpoint_auth_method"`
	TokenEndpointAuthSigningAlg types.String         `tfsdk:"token_endpoint_auth_signing_alg"`
	JwksURI                     types.String         `tfsdk:"jwks_uri"`
	Jwks                        jsontypes.Normalized `tfsdk:"jwks"`
	SubjectType                 types.String         `tfsdk:"subject_type"`
	SectorIdentifierURI         types.String         `tfsdk:"sector_identifier_uri"`
	UserinfoSignedResponseAlg   types.String         `tfsdk:"userinfo_signed_response_alg"`
	RequestObjectSigningAlg     types.String         `tfsdk:"request_object_signing_alg"`
	AccessTokenStrategy         types.String         `tfsdk:"access_token_strategy"`

	SkipConsent                       types.Bool   `tfsdk:"skip_consent"`
	SkipLogoutConsent                 types.Bool   `tfsdk:"skip_logout_consent"`
	FrontchannelLogoutURI             types.String `tfsdk:"frontchannel_logout_uri"`
	FrontchannelLogoutSessionRequired types.Bool   `tfsdk:"frontchannel_logout_session_required"`
	BackchannelLogoutURI              types.String `tfsdk:"backchannel_logout_uri"`
	BackchannelLogoutSessionRequired  types.Bool   `tfsdk:"backchannel_logout_session_required"`

	Metadata jsontypes.Normalized `tfsdk:"metadata"`

	AuthorizationCodeGrantAccessTokenLifespan    Duration `tfsdk:"authorization_code_grant_access_token_lifespan"`
	AuthorizationCodeGrantIDTokenLifespan        Duration `tfsdk:"authorization_code_grant_id_token_lifespan"`
	AuthorizationCodeGrantRefreshTokenLifespan   Duration `tfsdk:"authorization_code_grant_refresh_token_lifespan"`
	ClientCredentialsGrantAccessTokenLifespan    Duration `tfsdk:"client_credentials_grant_access_token_lifespan"`
	DeviceAuthorizationGrantAccessTokenLifespan  Duration `tfsdk:"device_authorization_grant_access_token_lifespan"`
	DeviceAuthorizationGrantIDTokenLifespan      Duration `tfsdk:"device_authorization_grant_id_token_lifespan"`
	DeviceAuthorizationGrantRefreshTokenLifespan Duration `tfsdk:"device_authorization_grant_refresh_token_lifespan"`
	ImplicitGrantAccessTokenLifespan             Duration `tfsdk:"implicit_grant_access_token_lifespan"`
	ImplicitGrantIDTokenLifespan                 Duration `tfsdk:"implicit_grant_id_token_lifespan"`
	JwtBearerGrantAccessTokenLifespan            Duration `tfsdk:"jwt_bearer_grant_access_token_lifespan"`
	RefreshTokenGrantAccessTokenLifespan         Duration `tfsdk:"refresh_token_grant_access_token_lifespan"`
	RefreshTokenGrantIDTokenLifespan             Duration `tfsdk:"refresh_token_grant_id_token_lifespan"`
	RefreshTokenGrantRefreshTokenLifespan        Duration `tfsdk:"refresh_token_grant_refresh_token_lifespan"`

	CreatedAt types.String `tfsdk:"created_at"`
	UpdatedAt types.String `tfsdk:"updated_at"`
}

func (m *oauth2ClientModel) lifespans() map[string]*Duration {
	return map[string]*Duration{
		"authorization_code_grant_access_token_lifespan":    &m.AuthorizationCodeGrantAccessTokenLifespan,
		"authorization_code_grant_id_token_lifespan":        &m.AuthorizationCodeGrantIDTokenLifespan,
		"authorization_code_grant_refresh_token_lifespan":   &m.AuthorizationCodeGrantRefreshTokenLifespan,
		"client_credentials_grant_access_token_lifespan":    &m.ClientCredentialsGrantAccessTokenLifespan,
		"device_authorization_grant_access_token_lifespan":  &m.DeviceAuthorizationGrantAccessTokenLifespan,
		"device_authorization_grant_id_token_lifespan":      &m.DeviceAuthorizationGrantIDTokenLifespan,
		"device_authorization_grant_refresh_token_lifespan": &m.DeviceAuthorizationGrantRefreshTokenLifespan,
		"implicit_grant_access_token_lifespan":              &m.ImplicitGrantAccessTokenLifespan,
		"implicit_grant_id_token_lifespan":                  &m.ImplicitGrantIDTokenLifespan,
		"jwt_bearer_grant_access_token_lifespan":            &m.JwtBearerGrantAccessTokenLifespan,
		"refresh_token_grant_access_token_lifespan":         &m.RefreshTokenGrantAccessTokenLifespan,
		"refresh_token_grant_id_token_lifespan":             &m.RefreshTokenGrantIDTokenLifespan,
		"refresh_token_grant_refresh_token_lifespan":        &m.RefreshTokenGrantRefreshTokenLifespan,
	}
}

func (r *oauth2ClientResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oauth2_client"
}

func (r *oauth2ClientResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.c = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func optStr(desc string) schema.StringAttribute {
	return schema.StringAttribute{Optional: true, MarkdownDescription: desc}
}

// serverStr is an optional attribute for which Hydra fills in a default.
func serverStr(desc string) schema.StringAttribute {
	return schema.StringAttribute{
		Optional: true, Computed: true, MarkdownDescription: desc + " Hydra fills in a default when omitted.",
		PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
	}
}

func serverBool(desc string) schema.BoolAttribute {
	return schema.BoolAttribute{
		Optional: true, Computed: true, MarkdownDescription: desc + " Defaults to `false` on the server.",
		PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
	}
}

func optList(desc string, v ...validator.List) schema.ListAttribute {
	return schema.ListAttribute{ElementType: types.StringType, Optional: true, MarkdownDescription: desc, Validators: v}
}

func (r *oauth2ClientResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed: true, MarkdownDescription: "Same as `client_id`.",
			PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"client_id": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "OAuth 2.0 client ID (immutable; changing it replaces the client). Import ID.",
			PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			Validators:          []validator.String{stringvalidator.LengthAtLeast(1)},
		},
		"client_secret_wo": schema.StringAttribute{
			Optional: true, WriteOnly: true, Sensitive: true,
			MarkdownDescription: "Write-only client secret (OpenTofu >= 1.11 / Terraform >= 1.11). " +
				"Sent to Hydra on create and whenever `client_secret_wo_version` changes; never stored in plan or state. " +
				"Required when creating a client whose `token_endpoint_auth_method` uses the secret " +
				"(`client_secret_basic` - the default -, `client_secret_post`, `client_secret_jwt`). Minimum 6 characters (Hydra).",
			Validators: []validator.String{stringvalidator.LengthAtLeast(6)},
		},
		"client_secret_wo_version": schema.Int64Attribute{
			Optional: true,
			MarkdownDescription: "Rotation trigger for `client_secret_wo`: change it (e.g. increment) to send the current " +
				"`client_secret_wo` to Hydra. Without a change the stored secret hash is left untouched.",
			Validators: []validator.Int64{int64validator.AlsoRequires(path.MatchRoot("client_secret_wo"))},
		},

		"client_name": optStr("Human-readable client name."),
		"owner":       optStr("Owner of the client."),
		"client_uri":  optStr("URL of the client's home page."),
		"logo_uri":    optStr("URL of the client's logo."),
		"policy_uri":  optStr("URL of the privacy policy."),
		"tos_uri":     optStr("URL of the terms of service."),
		"contacts":    optList("Contact e-mail addresses."),

		"grant_types": optList("Allowed grant types, e.g. `client_credentials`, `authorization_code`, `refresh_token`, "+
			"`urn:ietf:params:oauth:grant-type:jwt-bearer`, `urn:ietf:params:oauth:grant-type:device_code`. "+
			"Unknown values only produce a warning (Hydra does not validate this list).", grantTypesValidator{}),
		"response_types":            optList("Allowed response types (e.g. `code`, `id_token`, `token`)."),
		"scope":                     serverStr("Space-separated list of scopes the client may request."),
		"audience":                  optList("Allowed audiences for access tokens."),
		"redirect_uris":             optList("Allowed redirect URIs."),
		"post_logout_redirect_uris": optList("Allowed post-logout redirect URIs."),
		"allowed_cors_origins":      optList("Allowed CORS origins."),
		"request_uris":              optList("Allowed request URIs."),

		"token_endpoint_auth_method": func() schema.StringAttribute {
			a := serverStr("Token endpoint auth method: `client_secret_basic` (default), `client_secret_post`, `client_secret_jwt`, `private_key_jwt` or `none` (public client).")
			a.Validators = []validator.String{stringvalidator.OneOf("client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none")}
			return a
		}(),
		"token_endpoint_auth_signing_alg": optStr("Signing algorithm for `private_key_jwt` / `client_secret_jwt`."),
		"jwks_uri": schema.StringAttribute{
			Optional: true, MarkdownDescription: "URL of the client's JSON Web Key Set.",
			Validators: []validator.String{stringvalidator.ConflictsWith(path.MatchRoot("jwks"))},
		},
		"jwks": schema.StringAttribute{
			CustomType: jsontypes.NormalizedType{}, Optional: true,
			MarkdownDescription: "Inline JSON Web Key Set (public keys only) as a JSON string, e.g. `jsonencode({keys = [...]})`. " +
				"Every key needs `alg`, `kid`, `kty` and `use`. Prefer `jwks_uri`.",
			Validators: []validator.String{jwksValidator{}, stringvalidator.ConflictsWith(path.MatchRoot("jwks_uri"))},
		},
		"subject_type":          serverStr("Subject type: `public` or `pairwise`."),
		"sector_identifier_uri": optStr("Sector identifier URI (pairwise subjects)."),
		"userinfo_signed_response_alg": func() schema.StringAttribute {
			a := serverStr("Userinfo signing algorithm: `none` or `RS256`.")
			a.Validators = []validator.String{stringvalidator.OneOf("none", "RS256")}
			return a
		}(),
		"request_object_signing_alg": optStr("Request object signing algorithm."),
		"access_token_strategy": schema.StringAttribute{
			Optional: true, MarkdownDescription: "Per-client access token strategy (`opaque` or `jwt`), overrides `strategies.access_token`.",
			Validators: []validator.String{stringvalidator.OneOf("opaque", "jwt")},
		},

		"skip_consent":                         serverBool("Skip the consent screen."),
		"skip_logout_consent":                  serverBool("Skip the logout consent screen."),
		"frontchannel_logout_uri":              optStr("OIDC front-channel logout URI."),
		"frontchannel_logout_session_required": serverBool("Require `iss`/`sid` on front-channel logout."),
		"backchannel_logout_uri":               optStr("OIDC back-channel logout URI."),
		"backchannel_logout_session_required":  serverBool("Require `sid` in back-channel logout tokens."),

		"metadata": schema.StringAttribute{
			CustomType: jsontypes.NormalizedType{}, Optional: true, Computed: true,
			MarkdownDescription: "Arbitrary JSON metadata as a JSON string (compared semantically, e.g. `jsonencode({...})`).",
			PlanModifiers:       []planmodifier.String{jsonSemantic()},
		},

		"created_at": schema.StringAttribute{
			Computed: true, MarkdownDescription: "Creation timestamp.",
			PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"updated_at": schema.StringAttribute{Computed: true, MarkdownDescription: "Last update timestamp."},
	}
	for _, k := range lifespanKeys {
		attrs[k] = schema.StringAttribute{
			CustomType: DurationType{}, Optional: true, Computed: true,
			MarkdownDescription: "Token lifespan as a Go duration (`1h`, `10m`, `720h`); `10m` and `10m0s` are equal. Unset = Hydra's global default.",
			PlanModifiers:       []planmodifier.String{durationSemantic()},
		}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "OAuth 2.0 client of a self-hosted Ory Hydra (`/admin/clients`). " +
			"Updates use `PUT` (full replacement). The client secret is write-only and never stored in state.",
		Attributes: attrs,
	}
}

// ModifyPlan refuses (at plan time) to create a secret-authenticated client
// without client_secret_wo.
func (r *oauth2ClientResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return // destroy
	}
	creating := req.State.Raw.IsNull()
	if !creating {
		var stateID, planID types.String
		resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("client_id"), &stateID)...)
		resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("client_id"), &planID)...)
		creating = !planID.IsUnknown() && !stateID.Equal(planID) // replacement
	}
	if !creating {
		r.syncUpdatedAt(ctx, req, resp)
		return
	}
	resp.Diagnostics.Append(requireSecretOnCreate(ctx, req.Config)...)
}

// syncUpdatedAt decides updated_at for in-place plans. The framework marks
// the Computed updated_at unknown as soon as config and state differ
// textually - before attribute plan modifiers (semantic duration/JSON
// equality, lifespan reset) have run - and leaves it known when core's
// proposed state equals prior state even though a modifier then changed a
// value. So after all attribute modifiers: if nothing but updated_at differs
// from state, keep the state value (empty plan); otherwise mark it unknown.
func (r *oauth2ClientResource) syncUpdatedAt(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	var plan, state oauth2ClientModel
	resp.Diagnostics.Append(resp.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.UpdatedAt = state.UpdatedAt
	plan.ClientSecretWO, state.ClientSecretWO = types.StringNull(), types.StringNull()
	if reflect.DeepEqual(plan, state) {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("updated_at"), state.UpdatedAt)...)
		return
	}
	resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("updated_at"), types.StringUnknown())...)
}

type configGetter interface {
	GetAttribute(ctx context.Context, p path.Path, target any) diag.Diagnostics
}

func requireSecretOnCreate(ctx context.Context, cfg configGetter) diag.Diagnostics {
	var diags diag.Diagnostics
	var method, secret types.String
	diags.Append(cfg.GetAttribute(ctx, path.Root("token_endpoint_auth_method"), &method)...)
	diags.Append(cfg.GetAttribute(ctx, path.Root("client_secret_wo"), &secret)...)
	if diags.HasError() || method.IsUnknown() || secret.IsUnknown() {
		return diags
	}
	m := "client_secret_basic"
	if !method.IsNull() {
		m = method.ValueString()
	}
	if slices.Contains(secretAuthMethods, m) && secret.IsNull() {
		diags.AddAttributeError(path.Root("client_secret_wo"), "client_secret_wo is required",
			fmt.Sprintf("Creating a client with token_endpoint_auth_method = %q requires client_secret_wo. "+
				"Otherwise Hydra generates a secret which this provider deliberately never stores, leaving the client unusable. "+
				"Use token_endpoint_auth_method = \"none\" for public clients.", m))
	}
	return diags
}

func (r *oauth2ClientResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan oauth2ClientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(requireSecretOnCreate(ctx, req.Config)...)
	var secret types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("client_secret_wo"), &secret)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body, diags := plan.toAPI()
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !secret.IsNull() {
		body.ClientSecret = hydra.PtrString(secret.ValueString())
	}

	var got *hydra.OAuth2Client
	_, err := r.c.do(ctx, func() (*http.Response, error) {
		var hr *http.Response
		var err error
		got, hr, err = r.c.hydra.OAuth2API.CreateOAuth2Client(ctx).OAuth2Client(*body).Execute()
		return hr, err
	})
	if err != nil {
		addAPIError(&resp.Diagnostics, "Creating OAuth2 client failed", err)
		return
	}
	got.ClientSecret = nil // never keep it around

	got, err = r.reconcileLifespans(ctx, &plan, got)
	if err != nil {
		resp.Diagnostics.AddError("Setting OAuth2 client lifespans failed",
			fmt.Sprintf("Client %q was created but its lifespans could not be applied: %s", plan.ClientID.ValueString(), apiErrorDetail(err)))
		// Keep the created client in state so it is not orphaned.
	}

	resp.Diagnostics.Append(plan.fromAPI(got)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *oauth2ClientResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state oauth2ClientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := state.ClientID.ValueString()
	if id == "" {
		id = state.ID.ValueString()
	}

	var got *hydra.OAuth2Client
	hr, err := r.c.do(ctx, func() (*http.Response, error) {
		var hr *http.Response
		var err error
		got, hr, err = r.c.hydra.OAuth2API.GetOAuth2Client(ctx, id).Execute()
		return hr, err
	})
	if st := statusOf(hr); err != nil && (st == http.StatusNotFound || st == http.StatusUnauthorized) {
		// 404: deleted out of band. 401: what older Hydra versions answered
		// for unknown clients - kept for compatibility.
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		addAPIError(&resp.Diagnostics, "Reading OAuth2 client failed", err)
		return
	}
	resp.Diagnostics.Append(state.fromAPI(got)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *oauth2ClientResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state oauth2ClientModel
	var secret types.String
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("client_secret_wo"), &secret)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body, diags := plan.toAPI()
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	// PUT without client_secret keeps the stored hash (Hydra
	// persister.UpdateClient). Only send the secret when rotation is requested.
	if !secret.IsNull() && !plan.ClientSecretWOVersion.Equal(state.ClientSecretWOVersion) {
		body.ClientSecret = hydra.PtrString(secret.ValueString())
	}

	id := state.ClientID.ValueString()
	var got *hydra.OAuth2Client
	_, err := r.c.do(ctx, func() (*http.Response, error) {
		var hr *http.Response
		var err error
		got, hr, err = r.c.hydra.OAuth2API.SetOAuth2Client(ctx, id).OAuth2Client(*body).Execute()
		return hr, err
	})
	if err != nil {
		addAPIError(&resp.Diagnostics, "Updating OAuth2 client failed", err)
		return
	}
	got.ClientSecret = nil

	got, err = r.reconcileLifespans(ctx, &plan, got)
	if err != nil {
		addAPIError(&resp.Diagnostics, "Setting OAuth2 client lifespans failed", err)
		return
	}
	resp.Diagnostics.Append(plan.fromAPI(got)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *oauth2ClientResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state oauth2ClientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	hr, err := r.c.do(ctx, func() (*http.Response, error) {
		return r.c.hydra.OAuth2API.DeleteOAuth2Client(ctx, state.ClientID.ValueString()).Execute()
	})
	if err != nil && statusOf(hr) != http.StatusNotFound {
		addAPIError(&resp.Diagnostics, "Deleting OAuth2 client failed", err)
	}
}

func (r *oauth2ClientResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("client_id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

// reconcileLifespans applies PUT /admin/clients/{id}/lifespans when the
// lifespans Hydra reports differ from the planned ones.
func (r *oauth2ClientResource) reconcileLifespans(ctx context.Context, plan *oauth2ClientModel, got *hydra.OAuth2Client) (*hydra.OAuth2Client, error) {
	have, err := lifespansFromAPI(got)
	if err != nil {
		return got, err
	}
	want := map[string]any{}
	differ := false
	for k, v := range plan.lifespans() {
		var w string
		if !v.IsNull() && !v.IsUnknown() {
			w = v.ValueString()
			want[k] = w
		}
		h := have[k]
		if (w == "") != (h == "") || (w != "" && !durationsEqual(w, h)) {
			differ = true
		}
	}
	if !differ {
		return got, nil
	}
	var body hydra.OAuth2ClientTokenLifespans
	if err := jsonRoundTrip(want, &body); err != nil {
		return got, err
	}
	var updated *hydra.OAuth2Client
	_, err = r.c.do(ctx, func() (*http.Response, error) {
		var hr *http.Response
		var err error
		updated, hr, err = r.c.hydra.OAuth2API.SetOAuth2ClientLifespans(ctx, plan.ClientID.ValueString()).OAuth2ClientTokenLifespans(body).Execute()
		return hr, err
	})
	if err != nil {
		return got, err
	}
	updated.ClientSecret = nil
	return updated, nil
}

func lifespansFromAPI(c *hydra.OAuth2Client) (map[string]string, error) {
	m, err := c.ToMap()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, k := range lifespanKeys {
		if p, ok := m[k].(*string); ok && p != nil {
			out[k] = *p
		}
	}
	return out, nil
}

func jsonRoundTrip(in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// ---------------------------------------------------------------------------
// model <-> API mapping
// ---------------------------------------------------------------------------

func strPtr(v types.String) *string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	s := v.ValueString()
	return &s
}

func boolPtr(v types.Bool) *bool {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	b := v.ValueBool()
	return &b
}

func listVals(v types.List) []string {
	if v.IsNull() || v.IsUnknown() {
		return nil
	}
	out := make([]string, 0, len(v.Elements()))
	for _, e := range v.Elements() {
		if s, ok := e.(types.String); ok && !s.IsNull() && !s.IsUnknown() {
			out = append(out, s.ValueString())
		}
	}
	return out
}

func (m *oauth2ClientModel) toAPI() (*hydra.OAuth2Client, diag.Diagnostics) {
	var diags diag.Diagnostics
	c := hydra.OAuth2Client{
		ClientId:                          strPtr(m.ClientID),
		ClientName:                        strPtr(m.ClientName),
		Owner:                             strPtr(m.Owner),
		ClientUri:                         strPtr(m.ClientURI),
		LogoUri:                           strPtr(m.LogoURI),
		PolicyUri:                         strPtr(m.PolicyURI),
		TosUri:                            strPtr(m.TosURI),
		Contacts:                          listVals(m.Contacts),
		GrantTypes:                        listVals(m.GrantTypes),
		ResponseTypes:                     listVals(m.ResponseTypes),
		Scope:                             strPtr(m.Scope),
		Audience:                          listVals(m.Audience),
		RedirectUris:                      listVals(m.RedirectURIs),
		PostLogoutRedirectUris:            listVals(m.PostLogoutRedirectURIs),
		AllowedCorsOrigins:                listVals(m.AllowedCORSOrigins),
		RequestUris:                       listVals(m.RequestURIs),
		TokenEndpointAuthMethod:           strPtr(m.TokenEndpointAuthMethod),
		TokenEndpointAuthSigningAlg:       strPtr(m.TokenEndpointAuthSigningAlg),
		JwksUri:                           strPtr(m.JwksURI),
		SubjectType:                       strPtr(m.SubjectType),
		SectorIdentifierUri:               strPtr(m.SectorIdentifierURI),
		UserinfoSignedResponseAlg:         strPtr(m.UserinfoSignedResponseAlg),
		RequestObjectSigningAlg:           strPtr(m.RequestObjectSigningAlg),
		AccessTokenStrategy:               strPtr(m.AccessTokenStrategy),
		SkipConsent:                       boolPtr(m.SkipConsent),
		SkipLogoutConsent:                 boolPtr(m.SkipLogoutConsent),
		FrontchannelLogoutUri:             strPtr(m.FrontchannelLogoutURI),
		FrontchannelLogoutSessionRequired: boolPtr(m.FrontchannelLogoutSessionRequired),
		BackchannelLogoutUri:              strPtr(m.BackchannelLogoutURI),
		BackchannelLogoutSessionRequired:  boolPtr(m.BackchannelLogoutSessionRequired),
	}
	if !m.Metadata.IsNull() && !m.Metadata.IsUnknown() {
		var md any
		if err := json.Unmarshal([]byte(m.Metadata.ValueString()), &md); err != nil {
			diags.AddAttributeError(path.Root("metadata"), "Invalid metadata JSON", err.Error())
		}
		c.Metadata = md
	}
	if !m.Jwks.IsNull() && !m.Jwks.IsUnknown() {
		var set hydra.JsonWebKeySet
		if err := json.Unmarshal([]byte(m.Jwks.ValueString()), &set); err != nil {
			diags.AddAttributeError(path.Root("jwks"), "Invalid JWKS", err.Error())
		}
		c.Jwks = &set
	}
	ls := map[string]any{}
	for k, v := range m.lifespans() {
		if !v.IsNull() && !v.IsUnknown() {
			ls[k] = v.ValueString()
		}
	}
	if err := jsonRoundTrip(ls, &c); err != nil {
		diags.AddError("Internal error mapping lifespans", err.Error())
	}
	return &c, diags
}

// strFromAPI maps "" / absent to null, except when the prior value was an
// explicit empty string (keeps `x = ""` in config consistent).
func strFromAPI(v *string, prior types.String) types.String {
	if v == nil || *v == "" {
		if !prior.IsNull() && !prior.IsUnknown() && prior.ValueString() == "" {
			return prior
		}
		return types.StringNull()
	}
	return types.StringValue(*v)
}

func listFromAPI(v []string, prior types.List) types.List {
	if len(v) == 0 {
		if !prior.IsNull() && !prior.IsUnknown() && len(prior.Elements()) == 0 {
			return prior
		}
		return types.ListNull(types.StringType)
	}
	elems := make([]attr.Value, len(v))
	for i, s := range v {
		elems[i] = types.StringValue(s)
	}
	return types.ListValueMust(types.StringType, elems)
}

func boolFromAPI(v *bool) types.Bool {
	if v == nil {
		return types.BoolValue(false)
	}
	return types.BoolValue(*v)
}

func isEmptyJSON(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case map[string]any:
		return len(t) == 0
	}
	return false
}

func jwksKids(s string) []string {
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if json.Unmarshal([]byte(s), &set) != nil {
		return nil
	}
	kids := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		kids = append(kids, k.Kid)
	}
	slices.Sort(kids)
	return kids
}

// fromAPI overwrites m with what Hydra returned, using m's current values
// as "prior" for null/empty disambiguation. Write-only data is cleared.
func (m *oauth2ClientModel) fromAPI(c *hydra.OAuth2Client) diag.Diagnostics {
	var diags diag.Diagnostics
	m.ClientSecretWO = types.StringNull()
	m.ClientID = types.StringValue(c.GetClientId())
	m.ID = m.ClientID
	m.ClientName = strFromAPI(c.ClientName, m.ClientName)
	m.Owner = strFromAPI(c.Owner, m.Owner)
	m.ClientURI = strFromAPI(c.ClientUri, m.ClientURI)
	m.LogoURI = strFromAPI(c.LogoUri, m.LogoURI)
	m.PolicyURI = strFromAPI(c.PolicyUri, m.PolicyURI)
	m.TosURI = strFromAPI(c.TosUri, m.TosURI)
	m.Contacts = listFromAPI(c.Contacts, m.Contacts)
	m.GrantTypes = listFromAPI(c.GrantTypes, m.GrantTypes)
	m.ResponseTypes = listFromAPI(c.ResponseTypes, m.ResponseTypes)
	m.Scope = types.StringValue(c.GetScope())
	m.Audience = listFromAPI(c.Audience, m.Audience)
	m.RedirectURIs = listFromAPI(c.RedirectUris, m.RedirectURIs)
	m.PostLogoutRedirectURIs = listFromAPI(c.PostLogoutRedirectUris, m.PostLogoutRedirectURIs)
	m.AllowedCORSOrigins = listFromAPI(c.AllowedCorsOrigins, m.AllowedCORSOrigins)
	m.RequestURIs = listFromAPI(c.RequestUris, m.RequestURIs)
	m.TokenEndpointAuthMethod = types.StringValue(c.GetTokenEndpointAuthMethod())
	m.TokenEndpointAuthSigningAlg = strFromAPI(c.TokenEndpointAuthSigningAlg, m.TokenEndpointAuthSigningAlg)
	m.JwksURI = strFromAPI(c.JwksUri, m.JwksURI)
	m.SubjectType = types.StringValue(c.GetSubjectType())
	m.SectorIdentifierURI = strFromAPI(c.SectorIdentifierUri, m.SectorIdentifierURI)
	m.UserinfoSignedResponseAlg = types.StringValue(c.GetUserinfoSignedResponseAlg())
	m.RequestObjectSigningAlg = strFromAPI(c.RequestObjectSigningAlg, m.RequestObjectSigningAlg)
	m.AccessTokenStrategy = strFromAPI(c.AccessTokenStrategy, m.AccessTokenStrategy)
	m.SkipConsent = boolFromAPI(c.SkipConsent)
	m.SkipLogoutConsent = boolFromAPI(c.SkipLogoutConsent)
	m.FrontchannelLogoutURI = strFromAPI(c.FrontchannelLogoutUri, m.FrontchannelLogoutURI)
	m.FrontchannelLogoutSessionRequired = boolFromAPI(c.FrontchannelLogoutSessionRequired)
	m.BackchannelLogoutURI = strFromAPI(c.BackchannelLogoutUri, m.BackchannelLogoutURI)
	m.BackchannelLogoutSessionRequired = boolFromAPI(c.BackchannelLogoutSessionRequired)

	// metadata
	if isEmptyJSON(c.Metadata) {
		if m.Metadata.IsNull() || m.Metadata.IsUnknown() || !isEmptyJSONString(m.Metadata.ValueString()) {
			m.Metadata = jsontypes.NewNormalizedNull()
		}
	} else {
		b, err := json.Marshal(c.Metadata)
		if err != nil {
			diags.AddError("Encoding metadata failed", err.Error())
		} else {
			m.Metadata = jsontypes.NewNormalizedValue(string(b))
		}
	}

	// jwks: Hydra re-serialises keys, so keep the configured text as long as
	// the set of key IDs is unchanged; take the server value otherwise.
	if c.Jwks == nil || len(c.Jwks.Keys) == 0 {
		m.Jwks = jsontypes.NewNormalizedNull()
	} else {
		b, err := json.Marshal(c.Jwks)
		if err != nil {
			diags.AddError("Encoding jwks failed", err.Error())
		} else if m.Jwks.IsNull() || m.Jwks.IsUnknown() || !slices.Equal(jwksKids(m.Jwks.ValueString()), jwksKids(string(b))) {
			m.Jwks = jsontypes.NewNormalizedValue(string(b))
		}
	}

	ls, err := lifespansFromAPI(c)
	if err != nil {
		diags.AddError("Reading lifespans failed", err.Error())
	}
	for k, v := range m.lifespans() {
		if s, ok := ls[k]; ok && s != "" {
			if !v.IsNull() && !v.IsUnknown() && durationsEqual(v.ValueString(), s) {
				continue // keep the configured spelling ("10m" vs "10m0s")
			}
			*v = NewDurationValue(s)
		} else {
			*v = NewDurationNull()
		}
	}

	// created_at is immutable; Hydra's create response and later reads can
	// differ by the sub-second rounding, so the first known value wins.
	if c.CreatedAt != nil && (m.CreatedAt.IsNull() || m.CreatedAt.IsUnknown()) {
		m.CreatedAt = types.StringValue(c.CreatedAt.UTC().Format(time.RFC3339))
	} else if m.CreatedAt.IsUnknown() {
		m.CreatedAt = types.StringNull()
	}
	if c.UpdatedAt != nil {
		m.UpdatedAt = types.StringValue(c.UpdatedAt.UTC().Format(time.RFC3339Nano))
	} else {
		m.UpdatedAt = types.StringNull()
	}
	return diags
}

func isEmptyJSONString(s string) bool {
	var v any
	return json.Unmarshal([]byte(s), &v) == nil && isEmptyJSON(v)
}

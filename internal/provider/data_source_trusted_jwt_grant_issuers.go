package provider

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	hydra "github.com/ory/hydra-client-go/v2"
)

var _ datasource.DataSourceWithConfigure = (*trustListDataSource)(nil)

// NewTrustedJWTGrantIssuersDataSource is the hydra_trusted_jwt_grant_issuers factory.
func NewTrustedJWTGrantIssuersDataSource() datasource.DataSource { return &trustListDataSource{} }

type trustListDataSource struct{ c *apiClient }

type trustListModel struct {
	Issuer  types.String      `tfsdk:"issuer"`
	Issuers []trustListEntity `tfsdk:"issuers"`
}

type trustListEntity struct {
	ID              types.String `tfsdk:"id"`
	Issuer          types.String `tfsdk:"issuer"`
	Subject         types.String `tfsdk:"subject"`
	AllowAnySubject types.Bool   `tfsdk:"allow_any_subject"`
	Scope           []string     `tfsdk:"scope"`
	Kid             types.String `tfsdk:"kid"`
	ExpiresAt       types.String `tfsdk:"expires_at"`
	CreatedAt       types.String `tfsdk:"created_at"`
}

func (d *trustListDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_trusted_jwt_grant_issuers"
}

func (d *trustListDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.c = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *trustListDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Lists trusted JWT Bearer grant issuers (optionally filtered by `issuer`). " +
			"Useful to find trust IDs for `import` blocks.",
		Attributes: map[string]schema.Attribute{
			"issuer": schema.StringAttribute{Optional: true, MarkdownDescription: "Only return trusts for this issuer."},
			"issuers": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"id":                schema.StringAttribute{Computed: true},
					"issuer":            schema.StringAttribute{Computed: true},
					"subject":           schema.StringAttribute{Computed: true},
					"allow_any_subject": schema.BoolAttribute{Computed: true},
					"scope":             schema.ListAttribute{Computed: true, ElementType: types.StringType},
					"kid":               schema.StringAttribute{Computed: true},
					"expires_at":        schema.StringAttribute{Computed: true},
					"created_at":        schema.StringAttribute{Computed: true},
				}},
			},
		},
	}
}

func (d *trustListDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg trustListModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var all []hydra.TrustedOAuth2JwtGrantIssuer
	token := ""
	for page := 0; page < 1000; page++ {
		var items []hydra.TrustedOAuth2JwtGrantIssuer
		hr, err := d.c.do(ctx, func() (*http.Response, error) {
			r := d.c.hydra.OAuth2API.ListTrustedOAuth2JwtGrantIssuers(ctx).PageSize(500)
			if !cfg.Issuer.IsNull() && cfg.Issuer.ValueString() != "" {
				r = r.Issuer(cfg.Issuer.ValueString())
			}
			if token != "" {
				r = r.PageToken(token)
			}
			var hr *http.Response
			var err error
			items, hr, err = r.Execute()
			return hr, err
		})
		if err != nil {
			addAPIError(&resp.Diagnostics, "Listing trusted JWT grant issuers failed", err)
			return
		}
		all = append(all, items...)
		token = nextPageToken(hr)
		if token == "" || len(items) == 0 {
			break
		}
	}
	cfg.Issuers = make([]trustListEntity, 0, len(all))
	for _, g := range all {
		e := trustListEntity{
			ID:              types.StringValue(g.GetId()),
			Issuer:          types.StringValue(g.GetIssuer()),
			Subject:         types.StringValue(g.GetSubject()),
			AllowAnySubject: types.BoolValue(g.GetAllowAnySubject()),
			Scope:           g.GetScope(),
			Kid:             types.StringValue(func() string { pk := g.GetPublicKey(); return pk.GetKid() }()),
			ExpiresAt:       types.StringNull(),
			CreatedAt:       types.StringNull(),
		}
		slices.Sort(e.Scope)
		if g.ExpiresAt != nil {
			e.ExpiresAt = NewTimestampValue(*g.ExpiresAt).StringValue
		}
		if g.CreatedAt != nil {
			e.CreatedAt = NewTimestampValue(*g.CreatedAt).StringValue
		}
		cfg.Issuers = append(cfg.Issuers, e)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}

// nextPageToken extracts page_token from a `Link: <...>; rel="next"` header.
func nextPageToken(hr *http.Response) string {
	if hr == nil {
		return ""
	}
	for _, link := range hr.Header.Values("Link") {
		for _, part := range strings.Split(link, ",") {
			if !strings.Contains(part, `rel="next"`) {
				continue
			}
			start, end := strings.Index(part, "<"), strings.Index(part, ">")
			if start < 0 || end <= start {
				continue
			}
			u, err := url.Parse(part[start+1 : end])
			if err != nil {
				continue
			}
			return u.Query().Get("page_token")
		}
	}
	return ""
}

package provider

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/attr/xattr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// ---------------------------------------------------------------------------
// Duration: a Go duration string ("10m", "1h30m") whose semantic equality is
// the parsed time.Duration, so "10m" == "10m0s" (Hydra always answers with
// time.Duration.String()).
// ---------------------------------------------------------------------------

// hydraDurationRe is the pattern Hydra's OpenAPI spec enforces for lifespans.
var hydraDurationRe = regexp.MustCompile(`^([0-9]+(ns|us|ms|s|m|h))+$`)

var (
	_ basetypes.StringTypable                    = DurationType{}
	_ basetypes.StringValuableWithSemanticEquals = Duration{}
	_ xattr.ValidateableAttribute                = Duration{}
)

// DurationType is the attr.Type of Duration values.
type DurationType struct{ basetypes.StringType }

func (t DurationType) String() string { return "provider.DurationType" }

func (t DurationType) ValueType(context.Context) attr.Value { return Duration{} }

func (t DurationType) Equal(o attr.Type) bool { _, ok := o.(DurationType); return ok }

func (t DurationType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return Duration{StringValue: in}, nil
}

func (t DurationType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	v, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	sv, ok := v.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T", v)
	}
	return Duration{StringValue: sv}, nil
}

// Duration is a string holding a Go duration.
type Duration struct{ basetypes.StringValue }

// NewDurationNull returns a null Duration.
func NewDurationNull() Duration { return Duration{StringValue: basetypes.NewStringNull()} }

// NewDurationValue returns a known Duration.
func NewDurationValue(s string) Duration { return Duration{StringValue: basetypes.NewStringValue(s)} }

func (v Duration) Type(context.Context) attr.Type { return DurationType{} }

func (v Duration) Equal(o attr.Value) bool {
	ov, ok := o.(Duration)
	return ok && v.StringValue.Equal(ov.StringValue)
}

func (v Duration) StringSemanticEquals(_ context.Context, nv basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	n, ok := nv.(Duration)
	if !ok {
		return false, diags
	}
	return durationsEqual(v.ValueString(), n.ValueString()), diags
}

func durationsEqual(a, b string) bool {
	if a == b {
		return true
	}
	da, err1 := time.ParseDuration(a)
	db, err2 := time.ParseDuration(b)
	return err1 == nil && err2 == nil && da == db
}

func (v Duration) ValidateAttribute(_ context.Context, req xattr.ValidateAttributeRequest, resp *xattr.ValidateAttributeResponse) {
	if v.IsNull() || v.IsUnknown() {
		return
	}
	s := v.ValueString()
	if !hydraDurationRe.MatchString(s) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid duration",
			fmt.Sprintf("%q must match %s (integer value + unit ns|us|ms|s|m|h, e.g. \"1h30m\").", s, hydraDurationRe))
		return
	}
	if _, err := time.ParseDuration(s); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid duration", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Timestamp: an RFC 3339 timestamp whose semantic equality is the instant
// rounded to whole seconds (Hydra stores trust expiry as UTC rounded to the
// second), so "2036-01-01T03:00:00+03:00" == "2036-01-01T00:00:00Z".
// ---------------------------------------------------------------------------

var (
	_ basetypes.StringTypable                    = TimestampType{}
	_ basetypes.StringValuableWithSemanticEquals = Timestamp{}
	_ xattr.ValidateableAttribute                = Timestamp{}
)

// TimestampType is the attr.Type of Timestamp values.
type TimestampType struct{ basetypes.StringType }

func (t TimestampType) String() string { return "provider.TimestampType" }

func (t TimestampType) ValueType(context.Context) attr.Value { return Timestamp{} }

func (t TimestampType) Equal(o attr.Type) bool { _, ok := o.(TimestampType); return ok }

func (t TimestampType) ValueFromString(_ context.Context, in basetypes.StringValue) (basetypes.StringValuable, diag.Diagnostics) {
	return Timestamp{StringValue: in}, nil
}

func (t TimestampType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	v, err := t.StringType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	sv, ok := v.(basetypes.StringValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type %T", v)
	}
	return Timestamp{StringValue: sv}, nil
}

// Timestamp is an RFC 3339 string.
type Timestamp struct{ basetypes.StringValue }

// NewTimestampValue formats t as RFC 3339 in UTC.
func NewTimestampValue(t time.Time) Timestamp {
	return Timestamp{StringValue: basetypes.NewStringValue(t.UTC().Format(time.RFC3339))}
}

// NewTimestampNull returns a null Timestamp.
func NewTimestampNull() Timestamp { return Timestamp{StringValue: basetypes.NewStringNull()} }

func (v Timestamp) Type(context.Context) attr.Type { return TimestampType{} }

func (v Timestamp) Equal(o attr.Value) bool {
	ov, ok := o.(Timestamp)
	return ok && v.StringValue.Equal(ov.StringValue)
}

func (v Timestamp) StringSemanticEquals(_ context.Context, nv basetypes.StringValuable) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics
	n, ok := nv.(Timestamp)
	if !ok {
		return false, diags
	}
	return timestampsEqual(v.ValueString(), n.ValueString()), diags
}

func timestampsEqual(a, b string) bool {
	if a == b {
		return true
	}
	ta, err1 := time.Parse(time.RFC3339Nano, a)
	tb, err2 := time.Parse(time.RFC3339Nano, b)
	return err1 == nil && err2 == nil && ta.Round(time.Second).Equal(tb.Round(time.Second))
}

// Time parses the value (callers must validate first).
func (v Timestamp) Time() (time.Time, error) { return time.Parse(time.RFC3339Nano, v.ValueString()) }

func (v Timestamp) ValidateAttribute(_ context.Context, req xattr.ValidateAttributeRequest, resp *xattr.ValidateAttributeResponse) {
	if v.IsNull() || v.IsUnknown() {
		return
	}
	if _, err := v.Time(); err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid RFC 3339 timestamp", err.Error())
	}
}

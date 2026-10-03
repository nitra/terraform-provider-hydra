package provider

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// semanticFromState is a plan modifier for Optional+Computed string
// attributes that carry a semantic-equality type (durations, timestamps,
// JSON). The framework only applies semantic equality to values returned by
// the provider, not when planning config against prior state, so after an
// import "10m" (config) vs "10m0s" (state) would otherwise show a diff.
//
// Behaviour:
//   - config null  -> plan null (attribute removed from config = unset in Hydra)
//   - config equal (semantically) to state -> plan keeps the state value
//   - otherwise    -> plan = config
//
// The attribute must be Computed: Terraform/OpenTofu reject plans in which a
// non-computed attribute differs from its configuration.
type semanticFromState struct {
	equal func(a, b string) bool
	desc  string
}

func (m semanticFromState) Description(context.Context) string { return m.desc }

func (m semanticFromState) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (m semanticFromState) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.ConfigValue.IsUnknown() {
		return
	}
	if req.ConfigValue.IsNull() {
		resp.PlanValue = types.StringNull()
		return
	}
	if req.StateValue.IsNull() || req.StateValue.IsUnknown() {
		resp.PlanValue = req.ConfigValue
		return
	}
	if m.equal(req.ConfigValue.ValueString(), req.StateValue.ValueString()) {
		resp.PlanValue = req.StateValue
		return
	}
	resp.PlanValue = req.ConfigValue
}

func durationSemantic() planmodifier.String {
	return semanticFromState{equal: durationsEqual, desc: "durations compare by value (10m == 10m0s)"}
}

func timestampSemantic() planmodifier.String {
	return semanticFromState{equal: timestampsEqual, desc: "timestamps compare by instant, rounded to seconds"}
}

func jsonSemantic() planmodifier.String {
	return semanticFromState{equal: jsonEqual, desc: "JSON compares structurally"}
}

func jsonEqual(a, b string) bool {
	var va, vb any
	if json.Unmarshal([]byte(a), &va) != nil || json.Unmarshal([]byte(b), &vb) != nil {
		return a == b
	}
	return reflect.DeepEqual(va, vb)
}

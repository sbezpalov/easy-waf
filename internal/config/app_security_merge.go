package config

import (
	"bytes"
	"encoding/json"
)

// MergeApplicationSecurityJSON merges a partial JSON object into base (PATCH semantics).
func MergeApplicationSecurityJSON(base ApplicationSecurity, patch []byte) (ApplicationSecurity, error) {
	baseMap, err := json.Marshal(base)
	if err != nil {
		return base, err
	}
	dec := json.NewDecoder(bytes.NewReader(patch))
	dec.UseNumber()
	var patchObj map[string]json.RawMessage
	if err := dec.Decode(&patchObj); err != nil {
		return base, err
	}
	var baseObj map[string]json.RawMessage
	if err := json.Unmarshal(baseMap, &baseObj); err != nil {
		return base, err
	}
	for k, v := range patchObj {
		baseObj[k] = v
	}
	merged, err := json.Marshal(baseObj)
	if err != nil {
		return base, err
	}
	var out ApplicationSecurity
	if err := json.Unmarshal(merged, &out); err != nil {
		return base, err
	}
	NormalizeApplicationSecurity(&out)
	return out, nil
}

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Duration is a time.Duration with JSON as human-readable strings ("24h", "30m", "50s", "1h30m")
// via time.ParseDuration, and as output from time.Duration.String().
// Unmarshal also accepts a JSON number (nanoseconds) for compatibility with older stored settings.
type Duration time.Duration

// MarshalJSON encodes as a quoted string, e.g. "24h".
func (d Duration) MarshalJSON() ([]byte, error) {
	u := time.Duration(d)
	if u == 0 {
		return []byte(`"0s"`), nil
	}
	return json.Marshal(u.String())
}

// UnmarshalJSON accepts a JSON string (time.ParseDuration) or a JSON number (nanoseconds).
func (d *Duration) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		*d = 0
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		if s == "" {
			*d = 0
			return nil
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("duration string %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	var i int64
	if err := json.Unmarshal(data, &i); err == nil {
		*d = Duration(time.Duration(i))
		return nil
	}
	var f float64
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("invalid duration JSON: %s", string(data))
	}
	*d = Duration(time.Duration(f))
	return nil
}

// Std returns the standard library duration.
func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

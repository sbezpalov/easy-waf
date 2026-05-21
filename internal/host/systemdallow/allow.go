// Package systemdallow is the shared systemd unit/action whitelist (no runner dependency).
package systemdallow

// AllowedUnits matches scripts/host/privileged.sh allowed_systemd_unit().
var AllowedUnits = []string{
	"easy-waf-api.service",
	"easy-waf-acmed.service",
	"haproxy.service",
	"crowdsec.service",
	"crowdsec-spoa-bouncer.service",
	"crowdsec-haproxy-spoa-bouncer.service",
	"fail2ban.service",
	"nftables.service",
	"postgresql.service",
}

var allowedActions = map[string]struct{}{
	"start":       {},
	"stop":        {},
	"restart":     {},
	"reload":      {},
	"enable":      {},
	"disable":     {},
	"try-restart": {},
}

var allowedUnits = func() map[string]struct{} {
	m := make(map[string]struct{}, len(AllowedUnits))
	for _, u := range AllowedUnits {
		m[u] = struct{}{}
	}
	return m
}()

// AllowedUnit reports whether unit is on the appliance whitelist.
func AllowedUnit(unit string) bool {
	_, ok := allowedUnits[unit]
	return ok
}

// AllowedAction reports whether action is on the appliance whitelist.
func AllowedAction(action string) bool {
	_, ok := allowedActions[action]
	return ok
}

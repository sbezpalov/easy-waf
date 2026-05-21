package acme

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/cloudns"
	"github.com/go-acme/lego/v4/providers/dns/httpreq"
	"github.com/go-acme/lego/v4/providers/dns/route53"
)

// DefaultDNSProvider is used when mode is dns-01 and dns_provider is empty.
const DefaultDNSProvider = "cloudns"

// IssueDNS01 runs ACME DNS-01 using Lego. Secrets must be supplied via env file (see docs/DNS01.md).
// dnsResolvers optionally overrides recursive resolvers for propagation checks (split-DNS; e.g. 1.1.1.1:53).
func IssueDNS01(ctx context.Context, email string, domains []string, staging bool, accountKeyPath, providerName, envFile string, dnsResolvers []string) (*certificate.Resource, error) {
	if email == "" || len(domains) == 0 {
		return nil, fmt.Errorf("email and domains required")
	}
	pn := strings.ToLower(strings.TrimSpace(providerName))
	if pn == "" {
		pn = DefaultDNSProvider
	}

	cleanup, err := ApplyEnvFromFile(envFile)
	if err != nil {
		return nil, fmt.Errorf("dns env: %w", err)
	}
	defer cleanup()

	p, err := newDNSProvider(pn)
	if err != nil {
		return nil, err
	}

	user, client, err := registerLegoClient(email, accountKeyPath, staging)
	if err != nil {
		return nil, err
	}

	var dnsOpts []dns01.ChallengeOption
	if ns := dns01.ParseNameservers(dnsResolvers); len(ns) > 0 {
		dnsOpts = append(dnsOpts, dns01.AddRecursiveNameservers(ns))
	}
	if err := client.Challenge.SetDNS01Provider(p, dnsOpts...); err != nil {
		return nil, err
	}

	if err := registerAccount(client, user); err != nil {
		return nil, err
	}

	req := certificate.ObtainRequest{Domains: domains, Bundle: true}
	res, err := client.Certificate.Obtain(req)
	if err != nil {
		return nil, err
	}
	_ = ctx
	return res, nil
}

func newDNSProvider(name string) (challenge.Provider, error) {
	switch name {
	case "cloudflare":
		return cloudflare.NewDNSProvider()
	case "cloudns":
		return cloudns.NewDNSProvider()
	case "route53":
		return route53.NewDNSProvider()
	case "webhook":
		return httpreq.NewDNSProvider()
	default:
		return nil, fmt.Errorf("unknown dns provider %q (use cloudflare, cloudns, route53, webhook)", name)
	}
}

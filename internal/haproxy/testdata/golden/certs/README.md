# Test certificates — not secrets

These `bundle-*.pem` files each contain a certificate **and its private key**, in
the single-file layout HAProxy expects for a `crt-list` entry.

They are **throwaway test material**, generated once for this repository:

| File | Subject | Not after |
|------|---------|-----------|
| `bundle-a.pem` | `CN=a.example.com` | 2035-01-01 |
| `bundle-b.pem` | `CN=b.example.org` | 2035-01-01 |
| `bundle-c.pem` | `CN=c.example.net` | 2035-01-01 |

All three are self-signed for `example.com` / `example.org` / `example.net` —
[reserved documentation domains](https://www.rfc-editor.org/rfc/rfc2606) that
nobody can own. The keys have never protected anything: they exist so that
`haproxy -c` can actually load the generated golden configurations in tests,
which is the only way to prove the renderer emits a configuration HAProxy accepts.

**Automated secret scanners will flag these files.** That is expected — a private
key in a repository is worth flagging. Before dismissing such a report, check that
the finding is one of the three files above and that the subject is an
`example.*` name. Any private key elsewhere in this repository is a real problem:
report it privately, see [SECURITY.md](../../../../../SECURITY.md).

Do not reuse these files for anything. An appliance generates its own management
certificate on first boot and obtains real certificates through ACME.

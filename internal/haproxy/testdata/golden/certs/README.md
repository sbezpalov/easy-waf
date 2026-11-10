# Test certificates are generated, not stored

`haproxy -c` has to open the PEM paths named in the golden configs. Those files
are written by `internal/testcert` when `go test ./internal/haproxy` starts
(`TestMain`), and by `scripts/test-backup-restore.sh` if it is run before that.

They are gitignored. Each one is a new self-signed certificate and private key
for `a.example.com`, `b.example.org` or `c.example.net`
([RFC 2606](https://www.rfc-editor.org/rfc/rfc2606) names). Do not commit them
and do not use them on an appliance.

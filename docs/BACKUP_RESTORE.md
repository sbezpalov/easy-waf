# Backup and restore

- **backup.sh** archives `/var/lib/easy-waf` and `/etc/easy-waf` into a tarball; **also** dump PostgreSQL (`pg_dump`) for full SME recovery.
- **restore.sh** extracts the archive next to the state directory; verify permissions and SELinux contexts after restore.
- Always run **Apply** in the UI (or `POST /api/v1/apply`) after restore to regenerate HAProxy configs if paths changed.

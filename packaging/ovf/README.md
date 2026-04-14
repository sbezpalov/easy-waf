# OVF / OVA packaging notes

## Goals

- Single appliance VM for hypervisors (VMware, Proxmox import, etc.).
- **Immutable secrets**: passwords and `DATABASE_URL` come from first-boot (cloud-init, vApp properties, or manual step).
- **Same codebase** as AlmaLinux bare-metal: only the delivery format differs.

## Build outline

1. Install AlmaLinux 10 in a VM with EFI or BIOS per target platform.
2. Run `scripts/install.sh` with `EASY_WAF_INSTALL_OS_PACKAGES=1` (local PostgreSQL is **on** by default; use `EASY_WAF_INSTALL_POSTGRES=0` if the DB is external).
3. Install CrowdSec + bouncer per product docs; place SPOE fragment under `/etc/haproxy/`.
4. Clear history and temporary files; optionally `cloud-init clean` for golden image.
5. Shut down and export OVF/OVA with **thin** or **thick** disk per ops policy.

## VMware / Proxmox

- **Resource planning:** [docs/VM-REQUIREMENTS.md](../../docs/VM-REQUIREMENTS.md) (vCPU, RAM, disk; ESXi vs QEMU–KVM).
- Install **open-vm-tools** or **qemu-guest-agent** for clean shutdown and IP reporting.
- Avoid shipping with a default password on `root`; use cloud-init user or lock root and sudo.

## Versioning

Tag OVA with product version + build ID; keep checksum (SHA256) next to the download.

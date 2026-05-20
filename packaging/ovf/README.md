# OVF / OVA packaging notes

## Goals

- Single appliance VM for hypervisors (VMware, Proxmox import, etc.).
- **Immutable secrets**: passwords and `DATABASE_URL` come from first-boot (cloud-init, autoinstall, vApp properties, or manual step).
- **Same codebase** as Ubuntu bare-metal: only the delivery format differs.

## Build outline

1. Install **Ubuntu 24.04 LTS** (server, minimal) in a VM with EFI or BIOS per target platform.
2. Run `scripts/install.sh` with `EASY_WAF_INSTALL_OS_PACKAGES=1` (local PostgreSQL is **on** by default; use `EASY_WAF_INSTALL_POSTGRES=0` if the DB is external).
3. Install CrowdSec + bouncer per product docs; place SPOE fragment under `/etc/haproxy/`.
4. Clear history and temporary files; optionally `cloud-init clean` for golden image.
5. Shut down and export OVF/OVA with **thin** or **thick** disk per ops policy.

Use **Ubuntu autoinstall** (subiquity) instead of kickstart — see [Ubuntu autoinstall documentation](https://ubuntu.com/server/docs/install/autoinstall).

## VMware / Proxmox

- **Resource planning:** [docs/VM-REQUIREMENTS.md](../../docs/VM-REQUIREMENTS.md) (vCPU, RAM, disk; ESXi vs QEMU–KVM).
- **VMware:** install **open-vm-tools** (`apt install open-vm-tools`).
- **Proxmox/KVM:** install **qemu-guest-agent** (`apt install qemu-guest-agent`).
- Avoid shipping with a default password on `root`; use cloud-init user or lock root and sudo.

## Versioning

Tag OVA with product version + build ID; keep checksum (SHA256) next to the download.

# Virtual machine sizing (ESXi / QEMU–KVM)

These numbers are **planning guidelines** for a single appliance running the full stack: **AlmaLinux**, **HAProxy**, **PostgreSQL** (local or co-located), **easy-waf-api**, **easy-waf-acmed**, optional **nginx**, **CrowdSec** (agent + LAPI + HAProxy SPOA bouncer), **fail2ban**, **firewalld**.

## Rough memory budget (why these sizes)

| Component | Typical RAM (order of magnitude) |
|-----------|----------------------------------|
| OS + systemd + sshd | ~300–600 MiB baseline |
| PostgreSQL (small config DB) | ~400–900 MiB (shared buffers + connections) |
| HAProxy | ~50–150 MiB |
| easy-waf-api + easy-waf-acmed (Go) | ~80–200 MiB combined |
| CrowdSec (crowdsec + spoa bouncer) | ~200–500 MiB |
| CrowdSec / OS page cache, spikes | headroom |

**Conclusion:** **2 GiB** is a tight minimum for **all-in-one**; **4 GiB** is comfortable for homelab with CrowdSec and leaves room for spikes and logs. **8 GiB** only if you expect many TLS handshakes, large IPBL maps, heavy CrowdSec collections, or you host other services on the same VM (not recommended).

## vCPU

- TLS + HAProxy are mostly I/O bound; **2 vCPU** suffice for typical home traffic (few dozen req/s, handful of hostnames).
- **4 vCPU** helps under burst TLS, ACME issuance, CrowdSec parsing, and PostgreSQL vacuum — use for **multi-tenant** or **heavier** lab traffic.

## Disk

| Use | Minimum | Recommended |
|-----|---------|-------------|
| OS (AlmaLinux minimal + updates) | ~8–12 GiB | ~16 GiB |
| `/var/lib/easy-waf` (certs, revisions, ACME webroot, IPBL maps) | ~2 GiB | ~8 GiB+ (growth) |
| PostgreSQL data (local) | ~2 GiB | ~8 GiB+ |
| Logs, CrowdSec data, package cache | ~2 GiB | ~4 GiB+ |

**Totals:** plan **≥ 32 GiB** vDisk for a durable appliance; **40–64 GiB** if you keep long logs or many cert revisions. Use **thin** provisioning on ESXi if storage is shared; pre-allocate for predictable performance on busy hosts.

## Profiles

| Profile | vCPU | RAM | Boot disk | Notes |
|---------|------|-----|-----------|--------|
| **Minimum (lab)** | 2 | 2 GiB | 32 GiB | External PostgreSQL only, or very light local DB; CrowdSec optional |
| **Recommended (homelab all-in-one)** | 2–4 | 4 GiB | 40–64 GiB | Local PostgreSQL + HAProxy + easy-waf + CrowdSec SPOA |
| **Comfort / growth** | 4 | 8 GiB | 64 GiB+ | Many published hostnames, larger IPBL feeds, CrowdSec AppSec paths |

## VMware ESXi

- **NIC:** **VMXNET3** (best throughput and offload support).
- **SCSI controller:** **Paravirtual** (PVSCSI) or LSI Logic per your ESXi version compatibility.
- **Guest tools:** **open-vm-tools** (clean shutdown, heartbeat, optional IP reporting).
- **Firmware:** BIOS or UEFI — match your OVF template and Secure Boot policy if used.
- **CPU/RAM:** no overcommit beyond cluster policy; reserve **1–2 GiB** if the host is busy.

## QEMU / KVM (Proxmox, virt-manager, libvirt)

- **Network:** **virtio** (`virtio-net`).
- **Disk:** **virtio-scsi** or **virtio-blk** for the system disk.
- **Guest agent:** **qemu-guest-agent** (time sync, fs trim, clean shutdown).
- **CPU model:** `host` or `host-passthrough` if your hypervisor docs allow (for AES-NI TLS); otherwise default `kvm64`/`qemu64` is fine for moderate load.

## Network

- One **vNIC** on the **front** segment (WAN / DMZ) is enough for the published gateway role; add a **second** vNIC only if you separate **management** (LAN) from **edge** at L2/L3.
- Do not rely on VM sizing for **management API exposure** — restrict **8443/tcp** with firewall and `management_allowed_cidrs` (see [SECURITY.md](SECURITY.md)).

## Snapshot and backup

- Size **disk** so snapshots and DB growth do not fill the datastore; PostgreSQL + `easy-waf` state under `/var/lib/easy-waf` should be included in backup scope.

See also [DEPLOYMENT.md](DEPLOYMENT.md) (OVF/OVA) and [packaging/ovf/README.md](../packaging/ovf/README.md).

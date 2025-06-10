# ProxMoxMonitorDash

This repository provides `Proxmox.sh`, a zero-input bootstrap script for a single-node Proxmox VE installation. It creates an AdGuard Home LXC container, configures DNS syncing and publishes DNS records for each guest to both AdGuard Home and Tailscale MagicDNS.

## Purpose
- Detect LAN settings and prepare an AdGuard Home container.
- Open required DNS ports in the Proxmox firewall.
- Install a Python helper that gathers IP addresses of the node and running containers.
- Sync those addresses to AdGuard Home and Tailscale every minute via systemd.

## Required dependencies
The script requires root access on Proxmox and uses the following tools:

- `bash`, `curl`, `jq`, `hexdump`, `iproute2`, `pveam`, `pvesm`, `pct`, `qm`, `systemctl`, `tailscale`
- Python 3 with the `requests` package

Missing packages are installed automatically. `nmap` is optional and speeds up IP detection if present.

## Setting the domain
Edit the `ZONE` variable near the top of `Proxmox.sh` to the domain you wish to use:

```bash
ZONE="example.com"
```

You can also change `CLUSTER_NAME` if you want a different alias for the host. Save the file after editing.

## Running the script
Execute the script as root:

```bash
sudo bash Proxmox.sh
```

It is safe to run multiple times since the operations are idempotent.

## Example DNS records
With `ZONE` set to `example.com` and a container named `adguard`, the helper will publish A records similar to:

```
proxmox.example.com 192.168.1.10
adguard.example.com 192.168.1.53
```

These records appear both in AdGuard Home and in your Tailscale MagicDNS configuration.

#!/usr/bin/env bash
# ============================================================================
#  setup-jke-hosted.sh  –  zero-input, idempotent bootstrap for “jke.hosted”
#  on a single-node Proxmox VE ≥ 8.4 homelab.
# ----------------------------------------------------------------------------
#  This script is *idempotent* – run it as many times as you like.  It will:
#    • Detect all LAN details (bridge, node IP, CIDR, free VMID/IP, tailnet)
#    • Create *or* recreate an AdGuard Home LXC
#    • Open DNS ports in the Proxmox firewall
#    • Install/update the DNS-sync Python helper and its systemd units
#    • Perform an immediate initial sync (MagicDNS + AdGuard rewrites)
# ----------------------------------------------------------------------------

set -Eeuo pipefail
trap 'echo "[ERROR] Script failed at line $LINENO. Aborting." >&2' ERR

log()   { echo "[INFO] $*"; }
warn()  { echo "[WARN] $*" >&2; }
error() { echo "[ERROR] $*" >&2; exit 1; }

# ----------------------------------------------------------------------------
# 0. Prerequisites check: bash, curl, jq, hexdump, tailscaled, pve tools
# ----------------------------------------------------------------------------
for cmd in bash curl jq hexdump ip pveam pvesm pct qm systemctl tailscale; do
  if ! command -v "$cmd" &>/dev/null; then
    log "Installing missing tool: $cmd"
    apt-get update -qq
    apt-get install -qq -y "${cmd}" || error "Failed to install $cmd"
  fi
done

# ----------------------------------------------------------------------------
# 1. Auto-detect LAN details
# ----------------------------------------------------------------------------
BRIDGE=$(ip route show default | awk '/default/ {print $5; exit}')
if [ -z "$BRIDGE" ]; then
  error "Cannot detect default bridge. Are you on Proxmox?"
fi

node_ip=$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')
GW_IP=$(ip route | awk '/^default/ {print $3; exit}')
if [ -z "$node_ip" ] || [ -z "$GW_IP" ]; then
  error "Failed to detect node IP or gateway."
fi

# Determine the prefix length of the bridge subnet
BR_ADDR_INFO=$(ip -4 -o addr show dev "$BRIDGE" | awk '{print $4; exit}')
if [ -z "$BR_ADDR_INFO" ]; then
  error "Cannot determine CIDR for bridge $BRIDGE."
fi
# Example: "192.168.1.10/24"
SUBNET_CIDR="$BR_ADDR_INFO"

# ----------------------------------------------------------------------------
# 2. Find free VMID ≥ 200 and an available IP (prefers *.53) for AdGuard LXC
# ----------------------------------------------------------------------------
USED_VMS=$(pct list | awk 'NR>1 {print $1}')
VMID=200
while printf '%s\n' $USED_VMS | grep -qx "$VMID"; do
  ((VMID++))
done

# Build an array of all host IPs in the subnet
# Use `nmap -sn` if installed, else ping-scan fallback
if command -v nmap &>/dev/null; then
  mapfile -t USED_IPS < <(nmap -sn "${SUBNET_CIDR}" -oG - | awk '/Up$/{print $2}')
else
  # Ping all addresses in the /24; could be slower but sufficient
  PREFIX=$(echo "$SUBNET_CIDR" | cut -d'/' -f1 | awk -F. '{printf "%d.%d.%d.", $1,$2,$3}')
  for i in {1..254}; do
    ip="${PREFIX}${i}"
    if ping -c1 -W1 "$ip" &>/dev/null; then
      USED_IPS+=("$ip")
    fi
  done
fi

# Pick .53 by default, else next unused
OCTETS=(${node_ip//./ })
BASE="${OCTETS[0]}.${OCTETS[1]}.${OCTETS[2]}."
if ! printf '%s\n' "${USED_IPS[@]}" | grep -qx "${BASE}53"; then
  ADG_IP="${BASE}53/${SUBNET_CIDR#*/}"
else
  for i in {2..254}; do
    candidate="${BASE}${i}"
    if ! printf '%s\n' "${USED_IPS[@]}" | grep -qx "$candidate"; then
      ADG_IP="${candidate}/${SUBNET_CIDR#*/}"
      break
    fi
  done
fi
if [ -z "${ADG_IP:-}" ]; then
  error "Unable to find a free IP for AdGuard in $SUBNET_CIDR."
fi

log "Detected bridge=$BRIDGE, node_ip=$node_ip, gw=$GW_IP, adguard_ip=$ADG_IP, vmid=$VMID"

# ----------------------------------------------------------------------------
# 3. Check/Create Proxmox API token for DNS sync
# ----------------------------------------------------------------------------
CONF_FILE=/etc/hosted-dns.conf

# Load zone/cluster/API key from config if present
if [ -f "$CONF_FILE" ]; then
  ZONE_FILE=$(awk -F= '/^zone[[:space:]]*=/{gsub(/^[ \t]+|[ \t]+$/, "", $2);print $2}' "$CONF_FILE")
  CLUSTER_FILE=$(awk -F= '/^cluster_name[[:space:]]*=/{gsub(/^[ \t]+|[ \t]+$/, "", $2);print $2}' "$CONF_FILE")
  KEY_FILE=$(awk -F= '/^api_key[[:space:]]*=/{gsub(/^[ \t]+|[ \t]+$/, "", $2);print $2}' "$CONF_FILE")
  SECRET=$(awk -F= '/^api_token_secret[[:space:]]*=/{gsub(/^[ \t]+|[ \t]+$/, "", $2);print $2}' "$CONF_FILE")
fi

# Allow environment variables to override config values
ZONE=${ZONE:-$ZONE_FILE}
CLUSTER_NAME=${CLUSTER_NAME:-$CLUSTER_FILE}
TS_API_KEY=${TS_API_KEY:-$KEY_FILE}

# Defaults if still unset
ZONE=${ZONE:-jke.hosted}
CLUSTER_NAME=${CLUSTER_NAME:-jke.hosted}
: ${TS_API_KEY:?TS_API_KEY must be set via env or $CONF_FILE}

# Create PVE API token if no secret was loaded
if [ -z "${SECRET:-}" ]; then
  if ! pveum user token info root@pam dnssync &>/dev/null; then
    SECRET=$(pveum user token add root@pam dnssync --comment "DNS-sync for jke.hosted" | awk '/secret/ {print $2}')
  else
    SECRET=$(pveum user token info root@pam dnssync | awk '/secret/ {print $2}')
  fi
fi

# ----------------------------------------------------------------------------
# 4. Find storage for LXC template vs. CT rootfs
# ----------------------------------------------------------------------------
TEMPLATE_STORAGE=$(pvesm status --content vztmpl 2>/dev/null | awk 'NR>1 {print $1; exit}')
CT_STORAGE=$(pvesm status --content rootdir 2>/dev/null | awk 'NR>1 {print $1; exit}')

if [ -z "$TEMPLATE_STORAGE" ]; then
  error "No storage supports LXC templates (vztmpl). Aborting."
fi
if [ -z "$CT_STORAGE" ]; then
  error "No storage supports LXC containers (rootdir). Aborting."
fi

log "Using TEMPLATE_STORAGE=$TEMPLATE_STORAGE and CT_STORAGE=$CT_STORAGE"

# Test CT_STORAGE for allocation
if ! pvesm alloc "$CT_STORAGE" 10M --vmid 0 &>/dev/null; then
  error "CT_STORAGE $CT_STORAGE cannot allocate container volumes. Aborting."
fi
pvesm free "$CT_STORAGE" 10M --vmid 0 &>/dev/null || true

# ----------------------------------------------------------------------------
# 5. Download Debian LXC template if missing
# ----------------------------------------------------------------------------
TEMPLATE_PREFIX="debian-12-standard"
log "Refreshing LXC template index..."
if ! pveam update; then
  error "'pveam update' failed. Aborting."
fi

TEMPLATE=$(pveam available --section system | grep -Eo "${TEMPLATE_PREFIX}_[0-9]+\.[0-9]+-[0-9]+_amd64\.tar\.zst" | head -n1)
if [ -z "$TEMPLATE" ]; then
  error "Debian 12 template not found in 'pveam available'. Aborting."
fi

if ! pveam list "$TEMPLATE_STORAGE" | grep -q "$TEMPLATE"; then
  log "Downloading LXC template $TEMPLATE to $TEMPLATE_STORAGE …"
  if ! pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"; then
    error "'pveam download $TEMPLATE' failed. Aborting."
  fi
fi

# ----------------------------------------------------------------------------
# 6. Create or recreate the AdGuard LXC (VMID=$VMID)
# ----------------------------------------------------------------------------
if pct status "$VMID" &>/dev/null; then
  warn "Container VMID $VMID exists – destroying for clean re-create …"
  pct stop "$VMID" || true
  pct destroy "$VMID" --purge 1
fi

log "Creating AdGuard LXC (VMID=$VMID) …"
pct create "$VMID" "$TEMPLATE_STORAGE":vztmpl/"$TEMPLATE" \
  --hostname adguard --cores 1 --memory 256 --swap 256 \
  --unprivileged 1 --features fuse=1 \
  --rootfs "$CT_STORAGE":4 \
  --net0 name=eth0,bridge="$BRIDGE",ip="$ADG_IP",gw="$GW_IP" \
  --onboot 1 --start 1

# Wait for the container to come up
echo "[INFO] Waiting 10s for AdGuard container to boot …"
sleep 10

# ----------------------------------------------------------------------------
# 7. Configure AdGuard Home inside the LXC
# ----------------------------------------------------------------------------
# Install inside the LXC: AdGuard's official auto-installer
pct exec "$VMID" -- bash -c "
apt-get update -qq
apt-get install -qq -y curl
curl -sSf https://static.adguard.com/adguardhome/release/AdGuardHome_linux_amd64.tar.gz \
  | tar -xz -C /opt &&
/opt/AdGuardHome/AdGuardHome -s install
"

# Generate and set AdGuard API token in its config
AG_API_TOKEN=$(hexdump -n16 -e '/1 \"%02x\"' /dev/urandom)
pct exec "$VMID" -- bash -c "
yq eval '.api.admin_api_key = \"$AG_API_TOKEN\"' -i /opt/AdGuardHome/AdGuardHome.yaml
systemctl restart adguardhome
"

# ----------------------------------------------------------------------------
# 8. Open DNS ports on Proxmox node firewall
# ----------------------------------------------------------------------------
# Check if firewall is enabled
if pve-firewall status | grep -q 'firewall is enabled'; then
  # TCP 53
  if ! pve-firewall localnet rule list | grep -q 'dport=53,proto=tcp'; then
    pve-firewall rule add --in --pos 1 --action ACCEPT --proto tcp --dport 53
  fi
  # UDP 53
  if ! pve-firewall localnet rule list | grep -q 'dport=53,proto=udp'; then
    pve-firewall rule add --in --pos 1 --action ACCEPT --proto udp --dport 53
  fi
fi

# ----------------------------------------------------------------------------
# 9. Write /etc/hosted-dns.conf (used by update-hosted-dns.py)
# ----------------------------------------------------------------------------
cat >"$CONF_FILE" <<EOF
[global]
zone          = ${ZONE}
cluster_name  = ${CLUSTER_NAME}

[tailscale]
api_key       = ${TS_API_KEY}
tailnet       = \$(tailscale status --json | jq -r .MagicDNSSuffix | sed 's/\.ts\.net\$//')

[adguard]
api_url       = http://${ADG_IP%/*}:3000
api_token     = ${AG_API_TOKEN}

[proxmox]
api_url        = https://${node_ip}:8006/api2/json
api_token_id   = root@pam!dnssync
api_token_secret = ${SECRET}
node_name      = $(hostname)
EOF
chmod 600 "$CONF_FILE"
log "Wrote $CONF_FILE"

# ----------------------------------------------------------------------------
# 10. Install/update update-hosted-dns.py helper
# ----------------------------------------------------------------------------
SYNC_BIN=/usr/local/bin/update-hosted-dns.py
cat >"$SYNC_BIN" <<'PYCODE'
#!/usr/bin/env python3
"""
update-hosted-dns.py – Sync Proxmox guests to AdGuard Home & Tailscale MagicDNS.

Idempotent; reads /etc/hosted-dns.conf for credentials/config.
"""
import sys, time, json, socket, requests, configparser
from urllib.parse import urljoin

# ----------------------------------------------------------------------------
# Load config
# ----------------------------------------------------------------------------
config = configparser.ConfigParser()
config.read("/etc/hosted-dns.conf")

ZONE = config["global"]["zone"]
CLUSTER = config["global"]["cluster_name"]

# Proxmox
PVE_URL = config["proxmox"]["api_url"]
PVE_TOKEN_ID = config["proxmox"]["api_token_id"]
PVE_TOKEN_SECRET = config["proxmox"]["api_token_secret"]
NODE = config["proxmox"]["node_name"]

# AdGuard
AG_URL = config["adguard"]["api_url"]
AG_TOKEN = config["adguard"]["api_token"]

# Tailscale
TS_API_KEY = config["tailscale"]["api_key"]
TAILNET = config["tailscale"]["tailnet"]
TS_API_BASE = f"https://api.tailscale.com/api/v2/tailnet/{TAILNET}/dns/names"

# Tailscale expects HTTP Basic with base64
import base64
HEADERS_TS = {
    "Authorization": "Basic " + base64.b64encode(f"{TS_API_KEY}:".encode()).decode()
}

HEADERS_AG = {"Authorization": f"Bearer {AG_TOKEN}"}

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def get_proxmox(url: str):
    resp = requests.get(
        urljoin(PVE_URL + "/", url),
        headers={"Authorization": f"PVEAPIToken={PVE_TOKEN_ID}={PVE_TOKEN_SECRET}"},
        verify=False,
    )
    resp.raise_for_status()
    return resp.json()

def get_guest_ips():
    """
    Returns a dict: { "proxmox": "node_ip", "<name>": "ip", ... }
    """
    # Start with the node itself
    node_ip = socket.gethostbyname(socket.gethostname())
    records = {"proxmox": node_ip, CLUSTER: node_ip}

    # LXC guests: /nodes/<node>/lxc
    lxc_list = get_proxmox(f"nodes/{NODE}/lxc")
    for item in lxc_list["data"]:
        vmid = item["vmid"]
        name = item["name"]
        if item["status"] != "running":
            continue
        # Attempt guest-agent first
        try:
            iface = get_proxmox(f"nodes/{NODE}/lxc/{vmid}/agent/network-get-interfaces")
            for entry in iface["result"]:
                if "ip-addresses" in entry and entry["ip-addresses"]:
                    ip = entry["ip-addresses"][0]["ip-address"]
                    records[name] = ip
                    break
        except Exception:
            # Fallback: parse /config (DHCP lease) or skip
            conf = get_proxmox(f"nodes/{NODE}/lxc/{vmid}/config")
            net0 = conf.get("data", {}).get("net0", "")
            if "ip=" in net0:
                ip = net0.split("ip=")[1].split("/")[0]
                records[name] = ip
    return records

def fetch_ag_rewrites():
    resp = requests.get(f"{AG_URL}/control/rewrite/list", headers=HEADERS_AG)
    resp.raise_for_status()
    return resp.json()["data"]

def fetch_ts_records():
    resp = requests.get(TS_API_BASE, headers=HEADERS_TS)
    resp.raise_for_status()
    return resp.json().get("names", [])

def sync_ag(desired):
    existing = fetch_ag_rewrites()
    existing_map = {item["domain"]: item for item in existing}

    # Create/update
    for fqdn, ip in desired.items():
        if fqdn in existing_map:
            if existing_map[fqdn]["answer"] != ip:
                requests.put(
                    f"{AG_URL}/control/rewrite/{existing_map[fqdn]['id']}",
                    json={"answer": ip},
                    headers=HEADERS_AG,
                ).raise_for_status()
        else:
            requests.post(
                f"{AG_URL}/control/rewrite/add",
                json={"domain": fqdn, "answer": ip},
                headers=HEADERS_AG,
            ).raise_for_status()

    # Delete orphans
    for item in existing:
        domain = item["domain"]
        if domain not in desired:
            requests.post(
                f"{AG_URL}/control/rewrite/delete",
                json={"id": item["id"]},
                headers=HEADERS_AG,
            ).raise_for_status()

def sync_ts(desired):
    existing = {item["domain_name"]: item for item in fetch_ts_records()}
    # Create/update
    for fqdn, ip in desired.items():
        if fqdn in existing:
            if existing[fqdn]["ip"] != ip:
                requests.put(
                    f"{TS_API_BASE}/{existing[fqdn]['id']}",
                    json={"ip": ip},
                    headers=HEADERS_TS,
                ).raise_for_status()
        else:
            requests.post(
                TS_API_BASE,
                json={"domain_name": fqdn, "ip": ip},
                headers=HEADERS_TS,
            ).raise_for_status()
    # Delete orphans
    for domain, rec in existing.items():
        if domain not in desired:
            requests.delete(
                f"{TS_API_BASE}/{rec['id']}",
                headers=HEADERS_TS,
            ).raise_for_status()

def write_dashboard(records):
    lines = [
        "<!DOCTYPE html>",
        "<html lang='en'><head><meta charset='UTF-8'><title>jke.hosted Hosts</title>",
        "<style>table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:8px}tr:nth-child(even){background:#f2f2f2}th{background:#4CAF50;color:white}</style>",
        "</head><body><h2>jke.hosted Host Directory</h2><table>",
        "<tr><th>Name</th><th>IP</th><th>SSH</th><th>Web</th></tr>",
    ]
    for name, ip in sorted(records.items()):
        fqdn = f"{name}.{ZONE}"
        ssh_link = f"ssh root@{fqdn}"
        web_url = f"http://{fqdn}"
        lines.append(f"<tr><td>{fqdn}</td><td>{ip}</td><td><a href='ssh://root@{fqdn}'>SSH</a></td><td><a href='{web_url}'>Web</a></td></tr>")
    lines.append("</table></body></html>")
    with open("/srv/http/hosts/index.html", "w") as f:
        f.write("\n".join(lines))

def main():
    desired = get_guest_ips()
    # Append domain suffix
    desired = {f"{name}.{ZONE}": ip for name, ip in desired.items()}

    sync_ag(desired)
    sync_ts(desired)
    write_dashboard(desired)

if __name__ == "__main__":
    main()
PYCODE

chmod +x "$SYNC_BIN"
log "Installed update-hosted-dns.py to $SYNC_BIN"

# ----------------------------------------------------------------------------
# 11. Deploy systemd units for one-shot + timer (1-minute cadence)
# ----------------------------------------------------------------------------
SERVICE_FILE=/etc/systemd/system/hosted-dns-sync.service
cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=Sync AdGuard & MagicDNS for jke.hosted
After=network-online.target tailscaled.service

[Service]
Type=oneshot
ExecStart=$SYNC_BIN
TimeoutStartSec=60
EOF

TIMER_FILE=/etc/systemd/system/hosted-dns-sync.timer
cat >"$TIMER_FILE" <<EOF
[Unit]
Description=Run hosted-dns-sync every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Verify and enable
systemd-analyze verify "$SERVICE_FILE" "$TIMER_FILE"
systemctl daemon-reload
systemctl enable --now hosted-dns-sync.timer
log "Enabled hosted-dns-sync.timer (runs every minute)"

# ----------------------------------------------------------------------------
# 12. Initial run of the sync helper
# ----------------------------------------------------------------------------
log "Performing initial DNS sync …"
"$SYNC_BIN"

log "Bootstrap complete. You can now access:"
log "  • Proxmox GUI: https://proxmox.${ZONE}:8006"
log "  • Landing page:  http://${CLUSTER}"
log "  • SSH:           ssh root@proxmox.${ZONE}"

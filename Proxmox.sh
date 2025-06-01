#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# -------------------- Root Check --------------------
if [[ $EUID -ne 0 ]]; then
  echo "Please run as root."
  exit 1
fi

# -------------------- Variables (override via ENV) --------------------
BASE_DOMAIN="${BASE_DOMAIN:-jke.hosted}"
MON_SUBDOMAIN="monitor.${BASE_DOMAIN}"
DNS_SUBDOMAIN="dns.${BASE_DOMAIN}"
AGH_USER="${AGH_USER:-admin}"
AGH_PASS="${AGH_PASS:-$(openssl rand -base64 12)}"
LN_DB_PASS="${LN_DB_PASS:-librenmspass}"
LN_USER="${LN_USER:-librenms}"
LN_PASS="${LN_PASS:-jkeAdmin@123}"
SNMP_COMM="${SNMP_COMM:-public}"

SNMPD_ID=900
FW_ID=901
ADG_ID=902
LN_ID=903

# -------------------- Helper Functions --------------------
say() { echo -e "\e[1;32m==> $1\e[0m"; }

clean_ct() {
  local id=$1
  if pct status "$id" &>/dev/null; then
    pct stop "$id" --skiplock 2>/dev/null || true
    pct destroy "$id"
  fi
}

ip_of() {
  local id=$1
  pct exec "$id" -- bash -lc "hostname -I 2>/dev/null | awk '{print \$1}'" || echo ""
}

wait_ip() {
  local id=$1; local ip=""
  for _ in {1..30}; do
    ip=$(ip_of "$id")
    [[ -n "$ip" ]] && { echo "$ip"; return; }
    sleep 2
  done
  echo ""
}

# -------------------- Host SNMPd --------------------
say "Installing SNMPd on host"
apt-get update -qq
if ! dpkg -l snmpd &>/dev/null; then
  apt-get install -y snmpd
fi
grep -q "^com2sec notConfigUser  default        $SNMP_COMM" /etc/snmp/snmpd.conf \
  || sed -i "s/^agentAddress  udp:127.0.0.1:161/agentAddress  udp:0.0.0.0:161\ncom2sec notConfigUser  default        $SNMP_COMM/" /etc/snmp/snmpd.conf
systemctl restart snmpd

# -------------------- Firewall on Host --------------------
say "Configuring host firewall"
# Allow SNMP
iptables -C INPUT -p udp --dport 161 -j ACCEPT 2>/dev/null || \
  iptables -A INPUT -p udp --dport 161 -j ACCEPT
# Allow management bridge traffic
iptables -C INPUT -i vmbr0 -j ACCEPT 2>/dev/null || \
  iptables -A INPUT -i vmbr0 -j ACCEPT
# Allow Tailscale if present
if ip link show tailscale0 &>/dev/null; then
  iptables -C INPUT -i tailscale0 -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -i tailscale0 -j ACCEPT
fi
iptables-save > /etc/iptables/rules.v4

# -------------------- Clean Existing Containers --------------------
say "Cleaning existing containers"
for id in "$SNMPD_ID" "$FW_ID" "$ADG_ID" "$LN_ID"; do
  clean_ct "$id"
done

# -------------------- Ensure Debian 12 LXC Template --------------------
say "Ensuring Debian 12 template"
TPL="local:vztmpl/debian-12-standard_12.0-1_amd64.tar.zst"
if ! pveam available | grep -q "debian-12"; then
  pveam update
fi
if ! pveam list | grep -q "debian-12"; then
  echo "Template debian-12 not found. Exiting."
  exit 1
fi

# -------------------- Container Creation --------------------
# All CTs share basic config
create_ct() {
  local id=$1 name=$2 netname=$3
  pct create "$id" "$TPL" \
    -hostname "$name" \
    -memory 2048 \
    -net0 name="$netname",bridge=vmbr0,ip=dhcp \
    -storage local-zfs \
    -cores 2
  pct set "$id" -features nesting=1
  pct start "$id"
}

say "Creating SNMPD container ($SNMPD_ID)"
create_ct "$SNMPD_ID" "snmpd-host" "eth0"
say "Creating Firewall container ($FW_ID)"
create_ct "$FW_ID" "fw-host" "eth0"
say "Creating AdGuard container ($ADG_ID)"
create_ct "$ADG_ID" "adguard" "eth0"
say "Creating LibreNMS container ($LN_ID)"
create_ct "$LN_ID" "librenms" "eth0"

# -------------------- Wait for IPs --------------------
say "Waiting for container IPs"
SNMPD_IP="$(wait_ip "$SNMPD_ID")"
FW_IP="$(wait_ip "$FW_ID")"
ADG_IP="$(wait_ip "$ADG_ID")"
LN_IP="$(wait_ip "$LN_ID")"
[[ -z "$SNMPD_IP" || -z "$FW_IP" || -z "$ADG_IP" || -z "$LN_IP" ]] && {
  echo "One or more containers did not get an IP. Exiting."
  exit 1
}

# -------------------- Configure SNMPd in Container --------------------
say "Configuring SNMPd in CT $SNMPD_ID"
pct exec "$SNMPD_ID" -- bash -lc "
  set -euo pipefail
  apt-get update -qq
  apt-get install -y snmpd
  sed -i \"s/^agentAddress  udp:127.0.0.1:161/agentAddress  udp:0.0.0.0:161\ncom2sec notConfigUser  default        $SNMP_COMM/\" /etc/snmp/snmpd.conf
  systemctl enable snmpd
  systemctl restart snmpd
"

# -------------------- Configure Firewall in Container --------------------
say "Configuring firewall in CT $FW_ID"
pct exec "$FW_ID" -- bash -lc "
  set -euo pipefail
  apt-get update -qq
  apt-get install -y iptables-persistent
  # Flush existing
  iptables -F
  # Allow DNS from AdGuard
  iptables -A INPUT -p tcp -s $ADG_IP --dport 53 -j ACCEPT
  iptables -A INPUT -p udp -s $ADG_IP --dport 53 -j ACCEPT
  # Allow HTTP from outside
  iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  # Allow LibreNMS to query SNMP container
  iptables -A INPUT -p udp -s $SNMPD_IP --dport 161 -j ACCEPT
  # Allow Proxmox host access
  iptables -A INPUT -s $(hostname -I | awk '{print \$1}') -j ACCEPT
  # Drop others
  iptables -P INPUT DROP
  netfilter-persistent save
"

# -------------------- Configure AdGuard Home --------------------
say "Configuring AdGuard Home in CT $ADG_ID"
pct exec "$ADG_ID" -- bash -lc "
  set -euo pipefail
  apt-get update -qq
  apt-get install -y curl
  # Install jq
  apt-get install -y jq
  # Fetch latest release URL
  URL=\"\$(curl -sSL https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest \
    | jq -r '.assets[] | select(.name|test(\"Linux_amd64\")) | .browser_download_url')\"
  cd /opt
  for i in {1..3}; do
    curl -sSL \"\$URL\" -o AdGuardHome.tar.gz && break || sleep 2
  done
  tar xzf AdGuardHome.tar.gz
  mv AdGuardHome /usr/local/bin/
  mkdir -p /etc/AdGuardHome
  cp /usr/local/bin/AdGuardHome/AdGuardHome.yaml /etc/AdGuardHome/
  # Configure admin credentials & DNS upstream
  yq eval \".dns.upstreamServers = [\\\"8.8.8.8\\\", \\\"8.8.4.4\\\"]\" -i /etc/AdGuardHome/AdGuardHome.yaml
  yq eval \".users = [{name: \\\"$AGH_USER\\\", password: \\\"$AGH_PASS\\\", is_admin: true}]\" -i /etc/AdGuardHome/AdGuardHome.yaml
  # Create systemd service
  cat > /etc/systemd/system/AdGuardHome.service <<'EOF'
[Unit]
Description=AdGuard Home
After=network.target
[Service]
ExecStart=/usr/local/bin/AdGuardHome/AdGuardHome --config /etc/AdGuardHome/AdGuardHome.yaml
User=root
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable AdGuardHome
  systemctl start AdGuardHome
  # Nginx reverse proxy
  apt-get install -y nginx
  cat > /etc/nginx/sites-available/adguard <<EOF
server {
    listen 80;
    server_name $MON_SUBDOMAIN;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
  ln -sf /etc/nginx/sites-available/adguard /etc/nginx/sites-enabled/adguard
  rm -f /etc/nginx/sites-enabled/default
  systemctl restart nginx
  # Allow DNS queries from FW container
  ufw allow from $FW_IP to any port 53 proto tcp
  ufw allow from $FW_IP to any port 53 proto udp
  ufw --force enable
"

# -------------------- Configure LibreNMS --------------------
say "Configuring LibreNMS in CT $LN_ID"
pct exec "$LN_ID" -- bash -lc "
  set -euo pipefail
  apt-get update -qq
  apt-get install -y git curl sudo
  # Install PHP and dependencies
  apt-get install -y apache2 mariadb-server mariadb-client software-properties-common
  add-apt-repository ppa:ondrej/php -y
  apt-get update -qq
  apt-get install -y php8.1 php8.1-{cli,gd,xml,mbstring,json,zip,zip,curl,ctype,session,fpm,mysql}
  # Restart services
  systemctl enable apache2 mariadb
  systemctl start apache2 mariadb
  # Setup database
  mysql -e \"CREATE DATABASE IF NOT EXISTS librenms CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\"
  mysql -e \"CREATE USER IF NOT EXISTS '$LN_USER'@'localhost' IDENTIFIED BY '$LN_DB_PASS';\"
  mysql -e \"GRANT ALL PRIVILEGES ON librenms.* TO '$LN_USER'@'localhost';\"
  mysql -e \"FLUSH PRIVILEGES;\"
  # Clone LibreNMS
  git clone https://github.com/librenms/librenms.git /opt/librenms
  chown -R www-data:www-data /opt/librenms
  chmod -R 755 /opt/librenms
  # PHP-FPM config
  PHPVER=\$(php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;')
  systemctl restart php\${PHPVER}-fpm
  # Apache vhost
  cat > /etc/apache2/sites-available/librenms.conf <<EOF
<VirtualHost *:80>
  ServerName $DNS_SUBDOMAIN
  DocumentRoot /opt/librenms/html
  <Directory "/opt/librenms/html">
    AllowOverride All
    Require all granted
  </Directory>
  ErrorLog /var/log/apache2/librenms-error.log
  CustomLog /var/log/apache2/librenms-access.log combined
</VirtualHost>
EOF
  a2ensite librenms
  a2enmod rewrite
  systemctl reload apache2
  # Finalize install
  su - www-data -s /bin/bash -c \"php /opt/librenms/build-base.php --dbhost=localhost --dbname=librenms --dbuser=$LN_USER --dbpass=$LN_DB_PASS --timezone=UTC --source=git\"
  # Create admin user
  su - www-data -s /bin/bash -c \"/opt/librenms/html/adduser.php $LN_PASS admin admin\"
  # CRON jobs
  (crontab -l www-data 2>/dev/null || true; echo '*/5 * * * * /opt/librenms/poller-wrapper.py  >> /dev/null 2>&1') | crontab -u www-data -
  apt-get install -y rrdtool
  # Allow SNMP from FW
  ufw allow from $FW_IP to any port 161 proto udp
  ufw --force enable
"

# -------------------- Snapshots --------------------
say "Creating snapshots"
for id in "$SNMPD_ID" "$FW_ID" "$ADG_ID" "$LN_ID"; do
  pct snapshot "$id" pristine
done

# -------------------- Summary --------------------
echo -e "\n==== Deployment Complete ===="
echo "Host SNMP available on: UDP port 161 (community: $SNMP_COMM)"
echo "SNMP CT IP: $SNMPD_IP"
echo "Firewall CT IP: $FW_IP"
echo "AdGuard Home: http://$MON_SUBDOMAIN  (user: $AGH_USER / pass: $AGH_PASS)"
echo "DNS queries forwarded by AdGuard to $DNS_SUBDOMAIN"
echo "LibreNMS: http://$DNS_SUBDOMAIN (admin password: $LN_PASS)"
echo "LibreNMS CT IP: $LN_IP"
echo "================================"

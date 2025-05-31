#!/usr/bin/env bash
# deploy-jke.sh (v36 – use jq endswith() for clean release lookup)
set -euo pipefail
IFS=$'\n\t'

say(){ printf '\n\033[1;32m▶ %s\033[0m\n' "$*"; }

say "Installing SNMPd and iptables-persistent…"
if ! dpkg -l snmpd &>/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y snmpd iptables-persistent &>/dev/null
else
  say "snmpd already installed, skipping"
fi

say "Configuring SNMPd…"
if ! grep -q '^rocommunity public' /etc/snmp/snmpd.conf; then
  cat >/etc/snmp/snmpd.conf <<'EOF'
agentAddress udp:161,udp6:[::1]:161
rocommunity public default -V systemonly
sysLocation    Homelab
sysContact     admin@localhost
EOF
  systemctl restart snmpd
else
  say "snmpd.conf already configured, skipping"
fi

say "Applying host firewall rules…"
if ! iptables -L INPUT | grep -q 'udp dpt:53'; then
  iptables -F
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -i vmbr0 -p udp --dport 53 -j ACCEPT
  iptables -A INPUT -i vmbr0 -p tcp --dport 53 -j ACCEPT
  iptables -A INPUT -i vmbr0 -p tcp --dport 80 -j ACCEPT
  iptables -A INPUT -i vmbr0 -p tcp --dport 443 -j ACCEPT
  iptables -A INPUT -i vmbr0 -p tcp --dport 22 -j ACCEPT
  iptables -A INPUT -i tailscale0 -j ACCEPT
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  netfilter-persistent save &>/dev/null
else
  say "Firewall rules already in place, skipping"
fi

say "Scheduling hourly host upgrades…"
HOST_CRON="0 * * * * apt-get update -qq && apt-get -y upgrade"
if crontab -l 2>/dev/null | grep -qxF "$HOST_CRON"; then
  say "host cron already present"
else
  (crontab -l 2>/dev/null || true; echo "$HOST_CRON") | crontab -
fi

# ─── LXC Basics ─────────────────────────────────────────────────────────────
BRIDGE="vmbr0"; STORAGE="local-zfs"; DNS_DOMAIN="jke.hosted"
HOST_A="$(hostname).${DNS_DOMAIN}"
HOST_IP="$(hostname -I | awk '{print $1}')"
DNS_CT=120; MON_CT=130; RP_CT=140

TPL=$(pveam list local \
  | awk '/debian-12-standard_.*_amd64/ {print $1}' \
  | sort -Vr | head -n1)
[[ -z "$TPL" ]] && { echo "✖ No Debian-12 template"; exit 1; }
[[ "$TPL" != *:vztmpl/* ]] && TPL="local:vztmpl/$TPL"
say "Using LXC template → $TPL"

ip_of(){ pct exec "$1" -- hostname -I | awk '{print $1}'; }
wait_ip(){
  local ip
  for _ in $(seq 1 30); do
    ip="$(ip_of "$1")"
    [[ -n "$ip" ]] && { echo "$ip"; return; }
    sleep 1
  done
  echo ""
}

clean_ct(){
  local id="$1"
  if pct list | awk '{print $1}' | grep -qw "$id"; then
    say "CT $id exists — destroying"
    pct shutdown "$id" --timeout 10 --forceStop 1 &>/dev/null || true
    pct stop     "$id" &>/dev/null || true
    pct destroy  "$id" --force 1 --purge 1 &>/dev/null || true
    for _ in $(seq 1 10); do
      ! pct list | awk '{print $1}' | grep -qw "$id" && return
      sleep 1
    done
    echo "✖ Failed to destroy CT $id"; exit 1
  fi
}

clean_ct "$DNS_CT"; clean_ct "$MON_CT"; clean_ct "$RP_CT"
say "Old CTs cleared. Starting deployment…"

# ─── 1) AdGuard Home CT ────────────────────────────────────────────────────
say "Deploying AdGuard Home CT $DNS_CT…"
if ! pct list | awk '{print $1}' | grep -qw "$DNS_CT"; then
  pct create "$DNS_CT" "$TPL" \
    --hostname dns --cores 1 --memory 256 --swap 256 \
    --rootfs "${STORAGE}":8 \
    --net0 name=eth0,bridge="$BRIDGE",ip=dhcp \
    --nameserver 1.1.1.1,8.8.8.8 \
    --unprivileged 1 --features nesting=1 \
    --tags jke,dns \
    --description "AdGuard Home DNS for $DNS_DOMAIN"
  pct start "$DNS_CT"
else
  say "CT $DNS_CT already exists, skipping"
fi

DNS_IP="$(wait_ip "$DNS_CT")"
[[ -z "$DNS_IP" ]] && { echo "✖ DHCP failed (AdGuard)"; exit 1; }

pct exec "$DNS_CT" -- bash -euxo pipefail <<EOF
DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none apt-get update -qq
DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none apt-get install -y \
  locales curl tar jq

if ! grep -q '^LANG=' /etc/default/locale; then
  printf 'LANG=en_GB.UTF-8\n' >/etc/default/locale
  printf 'en_GB.UTF-8 UTF-8\n' >/etc/locale.gen
  locale-gen && update-locale LANG=en_GB.UTF-8
fi

if [[ ! -x /opt/AdGuardHome/AdGuardHome ]]; then
  mkdir -p /opt
  url=\$(curl -sS https://api.github.com/repos/AdguardTeam/AdGuardHome/releases/latest \
    | jq -r '.assets[] | select(.name | endswith("linux_amd64.tar.gz")) | .browser_download_url')
  curl -sL "\$url" -o /opt/agh.tar.gz
  tar xzf /opt/agh.tar.gz -C /opt
  /opt/AdGuardHome/AdGuardHome -s install --no-check-update
fi

if ! grep -q 'bind_host: 0.0.0.0' /etc/AdGuardHome/AdGuardHome.yaml; then
  mkdir -p /etc/AdGuardHome
  cat >/etc/AdGuardHome/AdGuardHome.yaml <<'CFG'
bind_host: 0.0.0.0
http: { port: 80 }
dns:
  port: 53
  upstream_dns: [ "1.1.1.1","8.8.8.8" ]
  rewrites:
    - { domain: "$DNS_DOMAIN.monitor", answer: "0.0.0.0" }
    - { domain: "$HOST_A",           answer: "$HOST_IP" }
users:
  - { name: admin, password: jkePass@123 }
CFG
  systemctl restart AdGuardHome
fi
EOF

pct snapshot "$DNS_CT" pristine &>/dev/null || true

# ─── 2) LibreNMS CT ────────────────────────────────────────────────────────
say "Deploying LibreNMS CT $MON_CT…"
if ! pct list | awk '{print $1}' | grep -qw "$MON_CT"; then
  pct create "$MON_CT" "$TPL" \
    --hostname monitor --cores 2 --memory 2048 --swap 2048 \
    --rootfs "${STORAGE}":12 \
    --net0 name=eth0,bridge="$BRIDGE",ip=dhcp \
    --nameserver 1.1.1.1,8.8.8.8 \
    --unprivileged 1 --features nesting=1 \
    --tags jke,monitoring \
    --description "LibreNMS for LAN+host"
  pct start "$MON_CT"
else
  say "CT $MON_CT already exists, skipping"
fi

MON_IP="$(wait_ip "$MON_CT")"
[[ -z "$MON_IP" ]] && { echo "✖ DHCP failed (LibreNMS)"; exit 1; }

pct exec "$MON_CT" -- bash -euxo pipefail <<'EOF'
DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none apt-get update -qq
DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none apt-get install -y \
  locales acl python3-pip git nginx-full mariadb-server php-fpm php-mysql php-gd php-json \
  php-xml php-curl php-zip php-mbstring snmpd fping rrdtool graphviz composer jq

if ! grep -q '^LANG=' /etc/default/locale; then
  printf 'LANG=en_GB.UTF-8\n' >/etc/default/locale
  printf 'en_GB.UTF-8 UTF-8\n' >/etc/locale.gen
  locale-gen && update-locale LANG=en_GB.UTF-8
fi

service mysql start
if ! mysql -e 'SHOW DATABASES' | grep -qw librenms; then
  mysql -e "CREATE DATABASE librenms CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
fi
if ! mysql -e "SELECT User FROM mysql.user" | grep -qw librenms; then
  mysql -e "CREATE USER 'librenms'@'localhost' IDENTIFIED BY 'librenmspass';"
  mysql -e "GRANT ALL PRIVILEGES ON librenms.* TO 'librenms'@'localhost'; FLUSH PRIVILEGES;"
fi

if ! id librenms &>/dev/null; then
  useradd -M -d /opt/librenms -r -s /bin/bash librenms
fi
if [[ ! -d /opt/librenms ]]; then
  git clone -q https://github.com/librenms/librenms.git /opt/librenms
  chown -R librenms:librenms /opt/librenms
  su - librenms -c './scripts/composer_wrapper.php install --no-dev'
fi

if ! grep -q "db']['name']='librenms" /opt/librenms/config.php 2>/dev/null; then
  cat >/opt/librenms/config.php <<'PHP'
<?php
\$config['db']['host']='localhost';
\$config['db']['user']='librenms';
\$config['db']['pass']='librenmspass';
\$config['db']['name']='librenms';
\$config['webui']['theme']='dark';
\$config['snmp']['community']=['public'];
\$config['nets'][]='192.168.1.0/24';
\$config['nets'][]='100.64.0.0/10';
\$config['enable_weathermap']=1;
PHP
fi

if [[ ! -f /etc/nginx/sites-enabled/librenms.conf ]]; then
  cat >/etc/nginx/sites-enabled/librenms.conf <<'NG'
server {
  listen 80;
  server_name '${DNS_DOMAIN}'.monitor;
  root /opt/librenms/html;
  index index.php;
  location / { try_files \$uri \$uri/ /index.php?\$query_string; }
  location ~ \.php\$ {
    include fastcgi.conf;
    fastcgi_pass unix:/run/php/php-fpm.sock;
  }
}
NG
  systemctl restart nginx php8.1-fpm
fi

if ! crontab -l -u librenms 2>/dev/null | grep -qxF '*/5 * * * * librenms /usr/bin/php /opt/librenms/plugins/Weathermap/map-poller.php'; then
  echo '*/5 * * * * librenms /usr/bin/php /opt/librenms/plugins/Weathermap/map-poller.php' >/etc/cron.d/weathermap
fi

if ! su - librenms -c "php /opt/librenms/adduser.php" | grep -q admin; then
  su - librenms -c "php /opt/librenms/adduser.php admin jkeAdmin@123 10"
fi
EOF

pct snapshot "$MON_CT" pristine &>/dev/null || true

# ─── 3) Reverse-proxy CT ─────────────────────────────────────────────────────
say "Deploying reverse-proxy CT $RP_CT…"
if ! pct list | awk '{print $1}' | grep -qw "$RP_CT"; then
  pct create "$RP_CT" "$TPL" \
    --hostname rp --cores 1 --memory 512 --swap 512 \
    --rootfs "${STORAGE}":4 \
    --net0 name=eth0,bridge="$BRIDGE",ip=dhcp \
    --nameserver 1.1.1.1,8.8.8.8 \
    --unprivileged 1 --features nesting=1 \
    --tags jke,proxy \
    --description "NGINX RP for DNS & LibreNMS"
  pct start "$RP_CT"
else
  say "CT $RP_CT already exists, skipping"
fi

RP_IP="$(wait_ip "$RP_CT")"
[[ -z "$RP_IP" ]] && { echo "✖ DHCP failed (Proxy)"; exit 1; }

pct exec "$RP_CT" -- bash -euxo pipefail <<EOF
DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none apt-get update -qq
DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none apt-get install -y \
  locales nginx openssl

if ! grep -q '^LANG=' /etc/default/locale; then
  printf 'LANG=en_GB.UTF-8\n' >/etc/default/locale
  printf 'en_GB.UTF-8 UTF-8\n' >/etc/locale.gen
  locale-gen && update-locale LANG=en_GB.UTF-8
fi

if [[ ! -f /etc/nginx/ssl/ca.crt ]]; then
  mkdir -p /etc/nginx/ssl /usr/share/nginx/html
  openssl req -x509 -nodes -days 3650 -newkey rsa:4096 \
    -keyout /etc/nginx/ssl/ca.key \
    -out    /etc/nginx/ssl/ca.crt \
    -subj "/CN=JKE Homelab CA"
  openssl req -nodes -new \
    -keyout /etc/nginx/ssl/jke.key \
    -out    /etc/nginx/ssl/jke.csr \
    -subj "/CN=*.jke.hosted"
  openssl x509 -req \
    -in    /etc/nginx/ssl/jke.csr \
    -CA    /etc/nginx/ssl/ca.crt \
    -CAkey /etc/nginx/ssl/ca.key \
    -CAcreateserial \
    -out   /etc/nginx/ssl/jke.crt \
    -days 825
  cp /etc/nginx/ssl/ca.crt /usr/share/nginx/html/
fi

if [[ ! -f /etc/nginx/conf.d/reverse.conf ]]; then
  cat >/etc/nginx/conf.d/reverse.conf <<'CONF'
map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }

server {
  listen 80;
  server_name *.jke.hosted;
  root /usr/share/nginx/html;
  location / { try_files \$uri @https; }
  location @https { return 301 https://\$host\$request_uri; }
}

server {
  listen 443 ssl http2;
  server_name jke.hosted.monitor jke.hosted.dns;
  ssl_certificate     /etc/nginx/ssl/jke.crt;
  ssl_certificate_key /etc/nginx/ssl/jke.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_session_timeout 1d;

  location / { proxy_pass http://${MON_IP};    proxy_set_header Host \$host; }
  location /dns/ { rewrite ^/dns/(.*)\$ /\$1 break; proxy_pass http://${DNS_IP}/; }
  location = /ca.crt { root /usr/share/nginx/html; default_type application/x-x509-ca-cert; }
}
CONF
  nginx -t && systemctl restart nginx
fi
EOF

pct snapshot "$RP_CT" pristine &>/dev/null || true

# ─── Smoke-tests & Final ─────────────────────────────────────────────────────
say "Running smoke-tests…"
if dig @"${DNS_IP}" "${DNS_DOMAIN}.monitor" +short | grep -q "${MON_IP}"; then
  echo "✔ DNS OK"
else
  echo "✖ DNS failed"
fi
echo "→ DNS GUI:"   ; curl -skI "https://${DNS_DOMAIN}"        | head -n1
echo "→ LibreNMS:" ; curl -skI "https://${DNS_DOMAIN}.monitor" | head -n1

say "✅ Deployment complete!"
cat <<EOF

AdGuard:  https://${DNS_DOMAIN}         (admin/jkePass@123)
LibreNMS: https://${DNS_DOMAIN}.monitor  (admin/jkeAdmin@123)
CA:       https://${DNS_DOMAIN}/ca.crt

Host SNMP: public@udp/161
Firewall: vmbr0+tailscale0, ports 22,53,80,443 open

CT IPs: DNS=$DNS_IP  MON=$MON_IP  PROXY=$RP_IP

Next: trust the CA (https://${DNS_DOMAIN}/ca.crt), enable MagicDNS → $DNS_IP

Enjoy! 🚀
EOF

#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Single-binary VPN, all inside sing-box:
#   Server: vless+reality on TCP/443 (mobile/desktop clients)
#         + hysteria2     on UDP/443 (gateway client below)
#   Client: tun inbound  + hysteria2 outbound, with auto-updating
#           geoip-cn / geosite-cn rule sets (CN traffic exits direct).
#
# System Required: Ubuntu 26.04
#
# Important:
# This script is for learning bash operations.

# Pin a sing-box release. Bump as needed: https://github.com/SagerNet/sing-box/releases
singbox_version="1.13.11"
# Server pulls direct from GitHub (overseas host → fast).
singbox_url_gh="https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-amd64.tar.gz"
# Client may sit behind the GFW where GitHub is slow/unreliable. ghfast.top
# fronts GitHub releases. Swap to another mirror if this one rots —
# alternatives: mirror.ghproxy.com, gh-proxy.com, github.moeyy.xyz, github.akams.cn.
singbox_url_mirror="https://ghfast.top/https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-amd64.tar.gz"

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

exception() {
    echo -e "[${red}Error${plain}] ${1}" && exit 1
}

get_ip(){
    local IP=$( ip addr | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -Ev "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [[ -z ${IP} ]] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [[ -z ${IP} ]] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    echo ${IP}
}

ensure_service_user() {
    if ! id -u sing-box >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin sing-box
    fi
}

# Try a single URL. Returns 0 on success, nonzero on download/extract failure
# so the caller can fall through to another mirror.
install_singbox_from() {
    local url="$1"
    local tmp
    tmp=$(mktemp -d)
    trap "rm -rf '$tmp'" RETURN
    curl -fsSL --connect-timeout 10 --max-time 180 "$url" -o "$tmp/sb.tar.gz" || return 1
    tar -xzf "$tmp/sb.tar.gz" -C "$tmp" --strip-components=1 || return 1
    install -m 755 "$tmp/sing-box" /usr/local/bin/sing-box
}

# Server: GitHub direct only. Client: mirror first, then GitHub as fallback.
install_singbox() {
    local v="${singbox_version}"
    local gh mirror
    gh=$(printf "${singbox_url_gh}" "$v" "$v")
    mirror=$(printf "${singbox_url_mirror}" "$v" "$v")
    if [[ "${platform}" == "1" ]]; then
        install_singbox_from "$gh" || exception "Failed to download sing-box ${v} from GitHub"
    else
        if ! install_singbox_from "$mirror"; then
            echo "[${yellow}Warn${plain}] Mirror failed, falling back to GitHub direct..."
            install_singbox_from "$gh" || exception "Failed to download sing-box ${v} from mirror or GitHub"
        fi
    fi
}

# Self-signed cert for hysteria2's TLS layer. Hysteria2 auth still happens via
# its own password+obfs; client uses tls.insecure=true.
generate_self_signed_cert() {
    local cn="$1"
    mkdir -p /etc/sing-box/certs
    openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/key.pem 2>/dev/null
    openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/key.pem \
        -out /etc/sing-box/certs/cert.pem -subj "/CN=${cn}" 2>/dev/null
    chown -R sing-box:sing-box /etc/sing-box/certs
    chmod 600 /etc/sing-box/certs/key.pem
}

create_service() {
cat <<'SVC_EOF' > /etc/systemd/system/sing-box.service
[Unit]
Description=sing-box service
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
User=sing-box
Group=sing-box
ExecStart=/usr/local/bin/sing-box -D /var/lib/sing-box -C /etc/sing-box run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
SVC_EOF
    mkdir -p /var/lib/sing-box
    chown -R sing-box:sing-box /var/lib/sing-box /etc/sing-box
    systemctl daemon-reload
    systemctl enable sing-box.service
}

# IP forwarding for client gateway mode + bigger UDP buffers for hysteria2.
enable_ip_forward() {
cat <<'EOF' > /etc/sysctl.d/99-vpn.conf
net.ipv4.ip_forward=1
net.core.rmem_max=16777216
net.core.wmem_max=16777216
EOF
    sysctl --system >/dev/null
}

# All heredocs use quoted delimiters (<<'X') with ___PLACEHOLDER___ tokens
# replaced via sed. Avoids bash mangling values that start with digits
# (e.g. IPs like 199.x.x.x).

if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || exception "Run as root or install sudo."
    exec sudo -E bash "$0" "$@"
fi

echo "------ Choose your platform"
read -p "[1: Server, 2: Client]: " platform
[[ -z "${platform}" ]] && exception "Must choose your platform!"
if [[ "${platform}" != "1" ]] && [[ "${platform}" != "2" ]]; then
    exception "Platform must be ${yellow}1${plain}(Server) or ${yellow}2${plain}(Client)!"
fi

echo "------ Install dependencies"
apt update
apt install -y curl ca-certificates openssl tar

ensure_service_user
mkdir -p /etc/sing-box

if ! command -v sing-box >/dev/null 2>&1; then
    echo "------ Installing sing-box ${singbox_version}"
    install_singbox
fi

if [[ "${platform}" == "1" ]]; then
    # ====== SERVER ======
    echo "Reality serverName (a real TLS site to mimic)"
    read -p "Default(www.cloudflare.com): " reality_dest
    reality_dest="${reality_dest:-www.cloudflare.com}"

    echo "Hysteria2 password"
    read -p "Default(random): " hy2_password
    hy2_password="${hy2_password:-$(openssl rand -hex 16)}"

    echo "Hysteria2 obfs (salamander) password"
    read -p "Default(random): " hy2_obfs
    hy2_obfs="${hy2_obfs:-$(openssl rand -hex 16)}"

    echo "------ Generating Reality keys, UUID, short-id"
    keys_out=$(/usr/local/bin/sing-box generate reality-keypair)
    privkey=$(echo "$keys_out" | awk '/PrivateKey/ {print $2}')
    pubkey=$(echo "$keys_out"  | awk '/PublicKey/  {print $2}')
    uuid=$(/usr/local/bin/sing-box generate uuid)
    shortid=$(openssl rand -hex 8)

    echo "------ Generating self-signed TLS cert (for hysteria2)"
    generate_self_signed_cert "${reality_dest}"

    echo "------ Writing /etc/sing-box/config.json (server)"
cat <<'CFG_EOF' > /etc/sing-box/config.json
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [
    {
      "type": "vless",
      "tag": "reality-in",
      "listen": "::",
      "listen_port": 443,
      "users": [
        { "uuid": "___UUID___", "flow": "xtls-rprx-vision" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "___REALITY_DEST___",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "___REALITY_DEST___",
            "server_port": 443
          },
          "private_key": "___PRIVKEY___",
          "short_id": ["", "___SHORTID___"]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": 443,
      "obfs": { "type": "salamander", "password": "___HY2_OBFS___" },
      "users": [ { "password": "___HY2_PASSWORD___" } ],
      "tls": {
        "enabled": true,
        "certificate_path": "/etc/sing-box/certs/cert.pem",
        "key_path": "/etc/sing-box/certs/key.pem"
      }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}
CFG_EOF
    sed -i \
        -e "s|___UUID___|${uuid}|g" \
        -e "s|___REALITY_DEST___|${reality_dest}|g" \
        -e "s|___PRIVKEY___|${privkey}|g" \
        -e "s|___SHORTID___|${shortid}|g" \
        -e "s|___HY2_OBFS___|${hy2_obfs}|g" \
        -e "s|___HY2_PASSWORD___|${hy2_password}|g" \
        /etc/sing-box/config.json

else
    # ====== CLIENT ======
    echo "Enter your Server IP"
    read -p ": " server_ip
    [[ -z "${server_ip}" ]] && exception "Server IP must be set!"

    echo "Enter Hysteria2 password (from server install)"
    read -p ": " hy2_password
    [[ -z "${hy2_password}" ]] && exception "Hysteria2 password must be set!"

    echo "Enter Hysteria2 obfs (salamander) password (from server install)"
    read -p ": " hy2_obfs
    [[ -z "${hy2_obfs}" ]] && exception "Hysteria2 obfs password must be set!"

    echo "------ Writing /etc/sing-box/config.json (client)"
cat <<'CFG_EOF' > /etc/sing-box/config.json
{
  "log": { "level": "warn", "timestamp": true },
  "dns": {
    "servers": [
      { "type": "tls",   "tag": "remote", "server": "1.1.1.1",   "detour": "hy2-out" },
      { "type": "https", "tag": "china",  "server": "223.5.5.5" },
      { "type": "local", "tag": "system" }
    ],
    "rules": [
      { "rule_set": "geosite-cn",               "server": "china" },
      { "rule_set": "geosite-category-ads-all", "action": "reject" }
    ],
    "strategy": "ipv4_only",
    "final": "remote"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "address": ["172.19.0.1/30"],
      "mtu": 1400,
      "auto_route": true,
      "strict_route": true,
      "stack": "system"
    }
  ],
  "outbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-out",
      "server": "___SERVER_IP___",
      "server_port": 443,
      "obfs": { "type": "salamander", "password": "___HY2_OBFS___" },
      "password": "___HY2_PASSWORD___",
      "tls": { "enabled": true, "insecure": true }
    },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "rule_set": [
      {
        "type": "remote", "tag": "geoip-cn", "format": "binary",
        "url": "https://ghfast.top/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
        "download_detour": "direct", "update_interval": "168h"
      },
      {
        "type": "remote", "tag": "geosite-cn", "format": "binary",
        "url": "https://ghfast.top/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-cn.srs",
        "download_detour": "direct", "update_interval": "168h"
      },
      {
        "type": "remote", "tag": "geosite-category-ads-all", "format": "binary",
        "url": "https://ghfast.top/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
        "download_detour": "direct", "update_interval": "168h"
      }
    ],
    "rules": [
      { "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "ip_is_private": true, "outbound": "direct" },
      { "ip_cidr": ["223.5.5.5/32", "223.6.6.6/32"], "outbound": "direct" },
      { "rule_set": "geosite-category-ads-all", "action": "reject" },
      { "rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct" }
    ],
    "final": "hy2-out",
    "auto_detect_interface": true,
    "default_domain_resolver": "system"
  },
  "experimental": {
    "cache_file": { "enabled": true, "path": "/var/lib/sing-box/cache.db" }
  }
}
CFG_EOF
    sed -i \
        -e "s|___SERVER_IP___|${server_ip}|g" \
        -e "s|___HY2_OBFS___|${hy2_obfs}|g" \
        -e "s|___HY2_PASSWORD___|${hy2_password}|g" \
        /etc/sing-box/config.json
fi

chown -R sing-box:sing-box /etc/sing-box

echo "------ Enabling IP forwarding & UDP buffer tuning"
enable_ip_forward

echo "------ Checking kernel modules"
modprobe tun 2>/dev/null || echo "[${yellow}Warn${plain}] tun module not available — sing-box tun inbound may fail"

echo "------ Creating sing-box.service"
create_service

echo "------ Starting sing-box"
systemctl restart sing-box.service

sleep 2
if ! systemctl is-active --quiet sing-box; then
    echo -e "[${red}Error${plain}] sing-box failed to start. Check: ${yellow}journalctl -u sing-box -n 50${plain}"
    exit 1
fi

clear
if [[ "${platform}" == "1" ]]; then
    echo -e "Congratulations, ${green}Server${plain} install completed!"
    echo
    echo -e "${green}Reality (TCP/443)${plain} — for mobile / desktop clients (v2rayNG, etc.):"
    echo -e "  Address      : ${red} $(get_ip) ${plain}"
    echo -e "  Port         : ${red} 443 ${plain}"
    echo -e "  UUID         : ${red} ${uuid} ${plain}"
    echo -e "  Flow         : ${red} xtls-rprx-vision ${plain}"
    echo -e "  Public key   : ${red} ${pubkey} ${plain}"
    echo -e "  Short ID     : ${red} ${shortid} ${plain}"
    echo -e "  ServerName   : ${red} ${reality_dest} ${plain}"
    echo -e "  Fingerprint  : ${red} chrome ${plain}"
    echo
    echo -e "${green}Hysteria2 (UDP/443)${plain} — for the gateway client below:"
    echo -e "  Address          : ${red} $(get_ip) ${plain}"
    echo -e "  Port             : ${red} 443 ${plain}"
    echo -e "  Password         : ${red} ${hy2_password} ${plain}"
    echo -e "  Salamander obfs  : ${red} ${hy2_obfs} ${plain}"
    echo -e "  TLS              : ${red} self-signed (client uses insecure) ${plain}"
    echo
    echo -e "${red}Save the values above — you'll need them on the client!${plain}"
elif [[ "${platform}" == "2" ]]; then
    echo -e "Congratulations, ${green}Client${plain} install completed!"
    echo -e "To use this machine as a gateway, set other devices' default gateway to its LAN IP."
    echo
    echo -e "Health checks:"
    echo -e "  ${yellow}systemctl status sing-box${plain}"
    echo -e "  ${yellow}journalctl -u sing-box -f${plain}"
    echo -e "  ${yellow}curl https://ifconfig.me${plain}    # should return your server's IP"
fi

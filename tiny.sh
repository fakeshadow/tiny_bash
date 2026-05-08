#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Single-binary VPN, all inside sing-box:
#   Server: vless+reality on TCP/443 (mobile/desktop clients AND gateway).
#   Client: tun inbound + vless+reality outbound, with auto-updating
#           geoip-cn / geosite-cn rule sets (CN traffic exits direct).
#
# Why VLESS+Reality (TCP) and not hysteria2 (UDP/QUIC)?
# As of 2026 the GFW extracts SNI from QUIC Initial packets and throttles
# unrecognized flows within seconds; hysteria2 + Salamander has degraded
# to ~68% bypass rate. VLESS+Reality imitates a real Cloudflare TLS
# handshake at the byte level — currently the most GFW-resistant transport.
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

# IP forwarding for client gateway mode.
enable_ip_forward() {
cat <<'EOF' > /etc/sysctl.d/99-vpn.conf
net.ipv4.ip_forward=1
EOF
    sysctl --system >/dev/null
}

# Client-only: MSS clamp on forwarded TCP SYNs. LAN clients otherwise
# negotiate MSS=1460 (Ethernet 1500 - TCP/IP 40), oversize segments hit tun0
# at MTU 1380, and PMTUD recovery depends on ICMP "frag needed" reaching the
# LAN sender — which is frequently dropped by consumer routers, mobile
# stacks, or upstream firewalls. When PMTUD blackholes, large transfers
# (TLS Certificate, file downloads) silently stall. Clamping at SYN time
# bypasses PMTUD entirely.
nftables_configure_client_mss() {
cat <<'NFTEOF' > /etc/nftables.conf
#!/usr/sbin/nft -f

# Coexist with sing-box's auto_route managed table — only declare and flush
# our own, never the global ruleset.
add table inet vpngw_mss
flush table inet vpngw_mss

table inet vpngw_mss {
    chain forward {
        type filter hook forward priority filter; policy accept;
        tcp flags syn tcp option maxseg size set rt mtu
    }
}
NFTEOF
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
apt install -y curl ca-certificates openssl tar nftables

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

    echo "------ Generating Reality keys, UUID, short-id"
    keys_out=$(/usr/local/bin/sing-box generate reality-keypair)
    privkey=$(echo "$keys_out" | awk '/PrivateKey/ {print $2}')
    pubkey=$(echo "$keys_out"  | awk '/PublicKey/  {print $2}')
    uuid=$(/usr/local/bin/sing-box generate uuid)
    shortid=$(openssl rand -hex 8)

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
        /etc/sing-box/config.json

else
    # ====== CLIENT ======
    # All five values below are printed by the server install script — they
    # match the server's vless+reality inbound exactly, byte for byte.
    echo "Enter your Server IP"
    read -p ": " server_ip
    [[ -z "${server_ip}" ]] && exception "Server IP must be set!"

    echo "Enter Reality UUID (from server install)"
    read -p ": " reality_uuid
    [[ -z "${reality_uuid}" ]] && exception "UUID must be set!"

    echo "Enter Reality public key (from server install)"
    read -p ": " reality_pubkey
    [[ -z "${reality_pubkey}" ]] && exception "Public key must be set!"

    echo "Enter Reality short ID (from server install)"
    read -p ": " reality_shortid
    [[ -z "${reality_shortid}" ]] && exception "Short ID must be set!"

    echo "Enter Reality serverName (from server install)"
    read -p "Default(www.cloudflare.com): " reality_sni
    reality_sni="${reality_sni:-www.cloudflare.com}"

    echo "------ Writing /etc/sing-box/config.json (client)"
cat <<'CFG_EOF' > /etc/sing-box/config.json
{
  "log": { "level": "warn", "timestamp": true },
  "dns": {
    "servers": [
      { "type": "tls",   "tag": "remote", "server": "1.1.1.1",   "detour": "reality-out" },
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
      "mtu": 1380,
      "auto_route": true,
      "strict_route": true,
      "stack": "system"
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "reality-out",
      "server": "___SERVER_IP___",
      "server_port": 443,
      "uuid": "___UUID___",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "___SNI___",
        "utls": { "enabled": true, "fingerprint": "chrome" },
        "reality": {
          "enabled": true,
          "public_key": "___PUBKEY___",
          "short_id": "___SHORTID___"
        }
      }
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
    "final": "reality-out",
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
        -e "s|___UUID___|${reality_uuid}|g" \
        -e "s|___PUBKEY___|${reality_pubkey}|g" \
        -e "s|___SHORTID___|${reality_shortid}|g" \
        -e "s|___SNI___|${reality_sni}|g" \
        /etc/sing-box/config.json
fi

chown -R sing-box:sing-box /etc/sing-box

echo "------ Enabling IP forwarding & UDP buffer tuning"
enable_ip_forward

if [[ "${platform}" == "2" ]]; then
    echo "------ Configuring nftables MSS clamp (forwarded TCP through the tunnel)"
    nftables_configure_client_mss
    systemctl enable nftables 2>/dev/null || true
    systemctl restart nftables
fi

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
    echo -e "${green}Reality (TCP/443)${plain} — for both mobile / desktop clients AND the gateway:"
    echo -e "  Address      : ${red} $(get_ip) ${plain}"
    echo -e "  Port         : ${red} 443 ${plain}"
    echo -e "  UUID         : ${red} ${uuid} ${plain}"
    echo -e "  Flow         : ${red} xtls-rprx-vision ${plain}"
    echo -e "  Public key   : ${red} ${pubkey} ${plain}"
    echo -e "  Short ID     : ${red} ${shortid} ${plain}"
    echo -e "  ServerName   : ${red} ${reality_dest} ${plain}"
    echo -e "  Fingerprint  : ${red} chrome ${plain}"
    echo
    echo -e "${red}Save the values above — the client install will ask for all of them.${plain}"
elif [[ "${platform}" == "2" ]]; then
    echo -e "Congratulations, ${green}Client${plain} install completed!"
    echo -e "To use this machine as a gateway, set other devices' default gateway to its LAN IP."
    echo
    echo -e "Health checks:"
    echo -e "  ${yellow}systemctl status sing-box${plain}"
    echo -e "  ${yellow}journalctl -u sing-box -f${plain}"
    echo -e "  ${yellow}curl https://ifconfig.me${plain}    # should return your server's IP"
fi

#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Two-mode VPN install script.
#
# Server (mode 1): sing-box + vless+reality on TCP/443. Unchanged from the
#                  prior revision because it has been working reliably.
#
# Client (mode 2): xray + dokodemo-door TPROXY inbound + vless+reality
#                  outbound, as a transparent gateway for LAN devices.
#
# The client side follows Project X's official transparent-proxy guide,
# verbatim where possible. Source references are inlined next to each
# non-trivial config block:
#   * https://xtls.github.io/en/document/level-2/transparent_proxy/transparent_proxy.html
#   * https://xtls.github.io/en/document/level-2/tproxy.html
#   * https://xtls.github.io/en/document/level-2/tproxy_ipv4_and_ipv6.html
#   * https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-Vision-REALITY
#   * https://github.com/XTLS/Xray-install
#
# System Required: Ubuntu 26.04
#
# Important:
# This script is for learning bash operations.

# --- pinned versions / URLs ------------------------------------------------

# Server uses sing-box. Bump as needed: https://github.com/SagerNet/sing-box/releases
singbox_version="1.13.11"
singbox_url_gh="https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-amd64.tar.gz"
singbox_url_mirror="https://ghfast.top/https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-amd64.tar.gz"

# Client uses xray. Installed via the project's official one-liner — same
# tooling used by OpenWrt's luci-app-xray, OpenClash and others, so any
# breakage shows up in those communities first.
xray_install_url="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"

# TPROXY listening port on the gateway (xray's dokodemo-door inbound).
# Per xtls.github.io tproxy.html the default is 12345; no reason to change.
tproxy_port=12345

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

# --- server-only helpers (sing-box) ---------------------------------------

ensure_singbox_user() {
    if ! id -u sing-box >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin sing-box
    fi
}

install_singbox_from() {
    local url="$1"
    local tmp
    tmp=$(mktemp -d)
    trap "rm -rf '$tmp'" RETURN
    curl -fsSL --connect-timeout 10 --max-time 180 "$url" -o "$tmp/sb.tar.gz" || return 1
    tar -xzf "$tmp/sb.tar.gz" -C "$tmp" --strip-components=1 || return 1
    install -m 755 "$tmp/sing-box" /usr/local/bin/sing-box
}

install_singbox() {
    local v="${singbox_version}"
    local gh
    gh=$(printf "${singbox_url_gh}" "$v" "$v")
    install_singbox_from "$gh" || exception "Failed to download sing-box ${v} from GitHub"
}

create_singbox_service() {
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

# --- client-only helpers (xray + TPROXY) ----------------------------------

# Use the project-maintained installer. It writes /usr/local/bin/xray and
# /etc/systemd/system/xray.service with User=nobody + AmbientCapabilities
# including CAP_NET_ADMIN already, which is what TPROXY needs — confirmed
# by reading XTLS/Xray-install/install-release.sh.
install_xray() {
    bash -c "$(curl -L ${xray_install_url})" @ install || exception "xray install failed"
}

# Client config. Inbound block is the dokodemo-door TPROXY pattern from
# xtls.github.io/en/document/level-2/tproxy.html . Outbound block is the
# VLESS+Reality+Vision client template from
# https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-Vision-REALITY .
# `streamSettings.sockopt.mark = 255` (0xff) makes xray's own outbound
# traffic carry fwmark 0xff so the nftables rule below can RETURN it
# without sending it back through TPROXY (loop avoidance).
write_xray_client_config() {
    local server_ip="$1" uuid="$2" pubkey="$3" sid="$4" sni="$5" spiderx="$6"
cat <<'CFG_EOF' > /usr/local/etc/xray/config.json
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "tproxy-in",
      "listen": "0.0.0.0",
      "port": ___TPROXY_PORT___,
      "protocol": "dokodemo-door",
      "settings": {
        "network": "tcp,udp",
        "followRedirect": true
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": true
      },
      "streamSettings": {
        "sockopt": { "tproxy": "tproxy" }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "___SERVER_IP___",
            "port": 443,
            "users": [
              {
                "id": "___UUID___",
                "encryption": "none",
                "flow": "xtls-rprx-vision"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "fingerprint": "chrome",
          "serverName": "___SNI___",
          "publicKey": "___PUBKEY___",
          "shortId": "___SID___",
          "spiderX": "___SPIDERX___"
        },
        "sockopt": { "mark": 255 }
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom",
      "streamSettings": { "sockopt": { "mark": 255 } }
    },
    {
      "tag": "block",
      "protocol": "blackhole"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"],
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "network": "udp",
        "port": 53,
        "outboundTag": "direct"
      },
      {
        "type": "field",
        "network": "udp",
        "outboundTag": "block"
      },
      {
        "type": "field",
        "network": "tcp",
        "outboundTag": "proxy"
      }
    ]
  }
}
CFG_EOF
    sed -i \
        -e "s|___TPROXY_PORT___|${tproxy_port}|g" \
        -e "s|___SERVER_IP___|${server_ip}|g" \
        -e "s|___UUID___|${uuid}|g" \
        -e "s|___PUBKEY___|${pubkey}|g" \
        -e "s|___SID___|${sid}|g" \
        -e "s|___SNI___|${sni}|g" \
        -e "s|___SPIDERX___|${spiderx}|g" \
        /usr/local/etc/xray/config.json
}

# Translation of the canonical iptables/nftables rules from
# https://xtls.github.io/en/document/level-2/tproxy_ipv4_and_ipv6.html .
# The hex mark 0x000000ff and 0x00000001 values come from that doc; they
# are not magic numbers, they line up with the `mark: 255` set on xray's
# outbounds and the fwmark used by the policy routing service below.
write_tproxy_nftables() {
cat <<'NFTEOF' > /etc/nftables.conf
#!/usr/sbin/nft -f

# Idempotent: only flush our own table — coexists with whatever else the
# system may load (e.g. ufw / docker tables).
add table inet xray
flush table inet xray

table inet xray {
    chain prerouting {
        type filter hook prerouting priority filter; policy accept;

        # 1. Skip TPROXY for traffic that should never be proxied:
        #    loopback, multicast, broadcast.
        ip daddr { 127.0.0.0/8, 224.0.0.0/4, 255.255.255.255 } return

        # 2. LAN-internal TCP stays local. LAN-internal UDP also stays
        #    local UNLESS it is DNS (so we can intercept DNS to the
        #    gateway's IP if a client points there).
        meta l4proto tcp ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } return
        ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } udp dport != 53 return

        # 3. IPv6 link-local + unique-local mirror the v4 LAN exemptions.
        ip6 daddr { ::1, fe80::/10 } return
        meta l4proto tcp ip6 daddr fc00::/7 return
        ip6 daddr fc00::/7 udp dport != 53 return

        # 4. Loop avoidance: xray's own outbound packets (mark 0xff set
        #    via streamSettings.sockopt.mark) bypass TPROXY.
        meta mark 0x000000ff return

        # 5. Everything else: TPROXY to xray, mark with 0x1 so the policy
        #    routing rule below delivers the packet to the local socket.
        meta l4proto { tcp, udp } meta mark set 0x00000001 tproxy ip to 127.0.0.1:___TPROXY_PORT___ accept
        meta l4proto { tcp, udp } meta mark set 0x00000001 tproxy ip6 to [::1]:___TPROXY_PORT___ accept
    }
}
NFTEOF
    sed -i "s|___TPROXY_PORT___|${tproxy_port}|g" /etc/nftables.conf
}

# Policy routing: packets fwmark'd with 0x1 by the TPROXY rule are routed
# to "lo" (delivered to local socket) via dedicated tables 100 (v4) and
# 106 (v6). Numbers match xtls.github.io tproxy_ipv4_and_ipv6.html .
write_tproxy_route_service() {
cat <<'SVCEOF' > /etc/systemd/system/tproxy-route.service
[Unit]
Description=Policy routing for xray TPROXY (fwmark 0x1)
After=network-pre.target nftables.service
Wants=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
# Idempotent: ignore EEXIST on add, ignore ENOENT on del.
ExecStart=-/sbin/ip -4 rule add fwmark 1 table 100
ExecStart=-/sbin/ip -4 route add local default dev lo table 100
ExecStart=-/sbin/ip -6 rule add fwmark 1 table 106
ExecStart=-/sbin/ip -6 route add local default dev lo table 106
ExecStop=-/sbin/ip -4 rule del fwmark 1 table 100
ExecStop=-/sbin/ip -4 route flush table 100
ExecStop=-/sbin/ip -6 rule del fwmark 1 table 106
ExecStop=-/sbin/ip -6 route flush table 106

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable tproxy-route.service
}

# --- common helpers --------------------------------------------------------

enable_ip_forward() {
cat <<'EOF' > /etc/sysctl.d/99-vpn.conf
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
    sysctl --system >/dev/null
}

# All heredocs in this script use quoted delimiters (<<'X') with
# ___PLACEHOLDER___ tokens replaced via sed. Avoids bash mangling values
# that start with digits (e.g. IPs like 199.x.x.x).

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
# nftables is needed by the client (TPROXY rules); curl/openssl/tar are
# common to both modes (singbox download / reality keys / xray installer).
apt install -y curl ca-certificates openssl tar nftables iproute2

if [[ "${platform}" == "1" ]]; then
    # ============================ SERVER =================================
    ensure_singbox_user
    mkdir -p /etc/sing-box

    if ! command -v sing-box >/dev/null 2>&1; then
        echo "------ Installing sing-box ${singbox_version}"
        install_singbox
    fi

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

    chown -R sing-box:sing-box /etc/sing-box

    echo "------ Enabling IP forwarding"
    enable_ip_forward

    echo "------ Creating sing-box.service"
    create_singbox_service

    echo "------ Starting sing-box"
    systemctl restart sing-box.service

    sleep 2
    if ! systemctl is-active --quiet sing-box; then
        echo -e "[${red}Error${plain}] sing-box failed to start. Check: ${yellow}journalctl -u sing-box -n 50${plain}"
        exit 1
    fi

else
    # ============================ CLIENT =================================
    # All five Reality values come from the server install printout —
    # they must match the server's vless+reality inbound exactly.
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

    # spiderX is optional. If your server's reality 'dest' is an IP-only
    # endpoint, it can be empty; otherwise something like '/dns-query/'
    # is fine. See Xray-examples/VLESS-TCP-XTLS-Vision-REALITY/config_client.jsonc .
    echo "Enter Reality spiderX (optional, default empty)"
    read -p "Default(empty): " reality_spiderx

    if ! command -v xray >/dev/null 2>&1; then
        echo "------ Installing xray (XTLS/Xray-install)"
        install_xray
    fi

    echo "------ Writing /usr/local/etc/xray/config.json (client)"
    write_xray_client_config "${server_ip}" "${reality_uuid}" "${reality_pubkey}" "${reality_shortid}" "${reality_sni}" "${reality_spiderx}"

    echo "------ Writing /etc/nftables.conf (TPROXY rules)"
    write_tproxy_nftables

    echo "------ Writing tproxy-route.service (policy routing for fwmark 0x1)"
    write_tproxy_route_service

    echo "------ Enabling IP forwarding"
    enable_ip_forward

    echo "------ Starting nftables / tproxy-route / xray"
    systemctl enable nftables 2>/dev/null || true
    systemctl restart nftables
    systemctl restart tproxy-route.service
    systemctl restart xray.service

    sleep 2
    if ! systemctl is-active --quiet xray; then
        echo -e "[${red}Error${plain}] xray failed to start. Check: ${yellow}journalctl -u xray -n 50${plain}"
        exit 1
    fi
    if ! systemctl is-active --quiet tproxy-route; then
        echo -e "[${red}Error${plain}] tproxy-route failed. Check: ${yellow}journalctl -u tproxy-route -n 50${plain}"
        exit 1
    fi
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
else
    echo -e "Congratulations, ${green}Client${plain} install completed!"
    echo -e "Point your LAN devices' default gateway at this machine's LAN IP."
    echo
    echo -e "Health checks:"
    echo -e "  ${yellow}systemctl status xray nftables tproxy-route${plain}"
    echo -e "  ${yellow}journalctl -u xray -f${plain}"
    echo -e "  ${yellow}nft list table inet xray${plain}                # TPROXY rules"
    echo -e "  ${yellow}ip rule  | grep -i fwmark${plain}               # 'fwmark 0x1 lookup 100'"
    echo -e "  ${yellow}ip route show table 100${plain}                 # 'local default dev lo'"
    echo -e "  From a LAN device pointed at this gateway:"
    echo -e "  ${yellow}curl https://ifconfig.me${plain}                # should return the SERVER's IP"
fi

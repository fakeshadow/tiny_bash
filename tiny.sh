#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Two-mode VPN install script.
#
# Server (mode 1): sing-box with two inbounds:
#                    * vless+reality        on TCP/443  (primary, max stealth)
#                    * hysteria2+salamander on UDP/443  (UDP fallback,
#                                                        with port hopping)
#
# Client (mode 2): xray + dokodemo-door TPROXY inbound + vless+reality
#                  outbound, as a transparent gateway for LAN devices.
#                  Client uses Reality TCP only; the server's hy2 inbound
#                  is for external mobile/desktop clients that prefer UDP.
#
# Flow choice (asymmetric, by design):
#   * Server inbound:  "xtls-rprx-vision"           (only accepted value)
#   * Client outbound: "xtls-rprx-vision-udp443"    (this gateway only)
#
# The default Vision flow rejects UDP/443 client-side because QUIC over
# Vision is double-TLS (QUIC's own TLS 1.3 inside Vision's outer TLS 1.3)
# — wasteful when you can disable QUIC at the LAN client and let it fall
# back to TCP. We can't do that on a transparent gateway (every LAN
# device would need the toggle), so the gateway opts into the "-udp443"
# variant: it sets allowUDP443=true locally and strips the suffix
# (requestAddons.Flow = requestAddons.Flow[:16]) BEFORE the value hits
# the wire. The server therefore only ever sees "xtls-rprx-vision" and
# its inbound flow validator (which only accepts that exact string)
# stays happy. Sources:
#   * outbound.go (rejection + suffix strip): https://github.com/XTLS/Xray-core/blob/main/proxy/vless/outbound/outbound.go
#   * inbound.go (server-side flow validator): https://github.com/XTLS/Xray-core/blob/main/proxy/vless/inbound/inbound.go
#
# Non-443 UDP (Discord voice, NTP, game servers, etc.) is not affected
# by either guard — the rejection check only fires when port==443.
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

# Client uses xray. Bump as needed: https://github.com/XTLS/Xray-core/releases
xray_version="26.3.27"
# Ordered list of URL templates for the xray-core release zip. The script
# tries each in order and uses the first one that responds. Two %s slots:
# the version (without leading "v"), and the arch tag ("64" or "arm64-v8a").
#
# No single CN-friendly mirror is reliably up — what works rotates over time.
# If you find a better mirror, prepend it to this list. If they all die,
# the manual escape hatch is documented in install_xray() below.
# Each entry below was probed at script-write time: HTTP 200 + a real ZIP
# header byte (50 4b 03 04) on a range-GET, not just a HEAD ping. If you
# find a better mirror (or one of these dies), prepend/swap freely.
xray_url_templates=(
    "https://gh-proxy.com/https://github.com/XTLS/Xray-core/releases/download/v%s/Xray-linux-%s.zip"
    "https://ghfast.top/https://github.com/XTLS/Xray-core/releases/download/v%s/Xray-linux-%s.zip"
    "https://kkgithub.com/XTLS/Xray-core/releases/download/v%s/Xray-linux-%s.zip"
    "https://gh.ddlc.top/https://github.com/XTLS/Xray-core/releases/download/v%s/Xray-linux-%s.zip"
    "https://github.com/XTLS/Xray-core/releases/download/v%s/Xray-linux-%s.zip"
)

# TPROXY listening port on the gateway (xray's dokodemo-door inbound).
# Per xtls.github.io tproxy.html the default is 12345; no reason to change.
tproxy_port=12345

# Hysteria2 port-hopping range (server side). The hy2 socket binds only
# to UDP/443; an nftables NAT redirect maps this whole UDP range onto
# UDP/443 so clients can rotate ports to defeat per-port ISP throttling
# (China Telecom 163 backbone caps unclassified UDP flows at ~1 Mbps
# after sustained use of a single port). Range is wide on purpose —
# narrow ranges are themselves a fingerprint.
# Source: https://v2.hysteria.network/docs/advanced/Port-Hopping/
hy2_port_hop_start=20000
hy2_port_hop_end=50000

# CN-route bypass: weekly-refreshed list of CN-bound CIDRs loaded into an
# nftables set. Packets to those destinations RETURN early (skip TPROXY)
# and reach the local network direct via the kernel's normal forwarding
# path — zero userspace hop, full LAN throughput.
#
# Source: misakaio/chnroutes2 (BGP-derived, hourly upstream refresh, was
# already used by the original tiny.sh). IPv6 list isn't published by this
# project; v4 only.
#
# Each entry below was probed live (HTTP 200 + real CIDR file body), same
# proxies that work for the xray binary download.
chnroutes_url_templates=(
    "https://gh-proxy.com/https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
    "https://gh.ddlc.top/https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
    "https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
)

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

# Self-signed cert for hysteria2's TLS layer. Hy2 doesn't lean on the
# cert for identity (auth happens via password+salamander); the cert
# just provides the QUIC TLS 1.3 handshake bytes. Client uses
# tls.insecure=true. Salamander obfs runs OUTSIDE this TLS — it scrambles
# the QUIC packets themselves, so the GFW's QUIC SNI extractor sees noise
# and can't classify the flow as QUIC at all.
generate_self_signed_cert() {
    local cn="$1"
    mkdir -p /etc/sing-box/certs
    openssl ecparam -genkey -name prime256v1 -out /etc/sing-box/certs/key.pem 2>/dev/null
    openssl req -new -x509 -days 3650 -key /etc/sing-box/certs/key.pem \
        -out /etc/sing-box/certs/cert.pem -subj "/CN=${cn}" 2>/dev/null
    chown -R sing-box:sing-box /etc/sing-box/certs
    chmod 600 /etc/sing-box/certs/key.pem
}

# Hy2 port hopping: server hy2 binds one UDP/443 socket; the kernel NAT
# redirect maps the whole hy2_port_hop_start..end range onto UDP/443
# before sing-box sees the packet. Source IP is preserved (REDIRECT, not
# DNAT-to-remote), so per-user accounting / GeoIP still works.
# Source: https://v2.hysteria.network/docs/advanced/Port-Hopping/
nftables_configure_server_hy2_hop() {
cat <<NFTEOF > /etc/nftables.conf
#!/usr/sbin/nft -f
flush ruleset

table inet hy2_hop {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        udp dport ${hy2_port_hop_start}-${hy2_port_hop_end} redirect to :443
    }
}
NFTEOF
    chmod +x /etc/nftables.conf
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

# Try a single URL. Returns 0 on success, nonzero on download/extract
# failure so the caller can fall through to another mirror.
install_xray_from() {
    local url="$1"
    local tmp
    tmp=$(mktemp -d)
    trap "rm -rf '$tmp'" RETURN
    # Aggressive connect timeout so dead mirrors fail fast (we have several
    # to try). max-time stays generous for the 21MB transfer over slow links.
    curl -fsSL --connect-timeout 8 --max-time 180 "$url" -o "$tmp/xray.zip" || return 1
    unzip -q "$tmp/xray.zip" -d "$tmp/x" || return 1
    install -m 755 "$tmp/x/xray" /usr/local/bin/xray
    mkdir -p /usr/local/etc/xray
}

# Tries each entry of xray_url_templates in order. First success wins.
#
# Manual escape hatch — if all mirrors fail in your network:
#   1. From any machine with working GitHub access (e.g. your overseas
#      server), download and copy the zip to the gateway:
#        wget https://github.com/XTLS/Xray-core/releases/download/v${xray_version}/Xray-linux-64.zip
#        scp Xray-linux-64.zip gateway:/tmp/
#   2. On the gateway: pre-place the binary so this script's `command -v
#      xray` check short-circuits the download:
#        sudo unzip /tmp/Xray-linux-64.zip -d /tmp/xray
#        sudo install -m 755 /tmp/xray/xray /usr/local/bin/xray
#   3. Re-run sudo ./tiny.sh — install_xray will be skipped entirely.
install_xray() {
    local v="${xray_version}"
    local arch
    case "$(uname -m)" in
        x86_64|amd64) arch="64" ;;
        aarch64|arm64) arch="arm64-v8a" ;;
        *) exception "Unsupported architecture for xray: $(uname -m)" ;;
    esac
    local tmpl url
    for tmpl in "${xray_url_templates[@]}"; do
        url=$(printf "${tmpl}" "$v" "$arch")
        echo "------ Trying: ${url}"
        if install_xray_from "$url"; then
            echo "[${green}OK${plain}] xray ${v} installed."
            return 0
        fi
        echo "[${yellow}Warn${plain}] Failed; trying next mirror..."
    done
    exception "All xray mirrors failed. See manual escape hatch in install_xray() comment in tiny.sh."
}

# Replicates the systemd unit that XTLS/Xray-install/install-release.sh
# generates — User=nobody, ambient CAP_NET_ADMIN (needed for TPROXY bind),
# CAP_NET_BIND_SERVICE for low ports, RestartPreventExitStatus=23
# (xray's "configuration error" exit code, so a bad config doesn't churn).
create_xray_service() {
cat <<'XRAYSVC_EOF' > /etc/systemd/system/xray.service
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
XRAYSVC_EOF
    systemctl daemon-reload
    systemctl enable xray.service
}

# Client config. Inbound block is the dokodemo-door TPROXY pattern from
# xtls.github.io/en/document/level-2/tproxy.html . Outbound block is the
# VLESS+Reality+Vision client template from
# https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-Vision-REALITY .
# `streamSettings.sockopt.mark = 255` (0xff) makes xray's own outbound
# traffic carry fwmark 0xff so the nftables rule below can RETURN it
# without sending it back through TPROXY (loop avoidance).
#
# Note: sniffing.routeOnly is FALSE here, deviating from the SOCKS5-style
# template in Xray-examples (which uses true). The reason is that this is
# a transparent gateway — LAN clients pre-resolve hostnames via their own
# DNS, which gives them region-local edge IPs (CN-routed for CN clients).
# If we keep routeOnly:true, xray forwards "connect to <LAN-resolved-IP>"
# to the server, and the overseas server's outbound dial lands on a CN
# edge from a non-CN source. Strict geo-CDN sites (YouTube/googlevideo,
# some Akamai-fronted sites) RST that mid-TLS-handshake. With
# routeOnly:false, xray forwards the sniffed SNI hostname instead, and
# the server resolves it via its own DNS — source/destination regions
# match, the edge serves the request normally.
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
        "routeOnly": false
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
                "flow": "xtls-rprx-vision-udp443"
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
        "network": "tcp,udp",
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
    # CN-route bypass set. Populated/refreshed by /usr/local/sbin/update-chnroutes
    # via the include directive at the bottom of this file.
    set cn_ipv4 {
        type ipv4_addr
        flags interval
    }

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

        # 5. CN-bound traffic bypasses the proxy entirely — let the
        #    kernel's normal forwarding path send it out via WAN direct.
        ip daddr @cn_ipv4 return

        # 6. Everything else: TPROXY to xray, mark with 0x1 so the policy
        #    routing rule below delivers the packet to the local socket.
        meta l4proto { tcp, udp } meta mark set 0x00000001 tproxy ip to 127.0.0.1:___TPROXY_PORT___ accept
        meta l4proto { tcp, udp } meta mark set 0x00000001 tproxy ip6 to [::1]:___TPROXY_PORT___ accept
    }
}

# Populated weekly by /etc/cron.weekly/update-chnroutes. The file must
# exist (even as a placeholder) for nftables.service to start cleanly.
include "/etc/nftables.d/chnroutes.nft"
NFTEOF
    sed -i "s|___TPROXY_PORT___|${tproxy_port}|g" /etc/nftables.conf
}

# Writes the chnroutes updater + its weekly cron + an empty placeholder
# for the included nftables fragment. The placeholder is required because
# /etc/nftables.conf does `include "/etc/nftables.d/chnroutes.nft"` and
# nftables.service fails to start if the file is missing.
write_chnroutes_assets() {
    mkdir -p /etc/nftables.d
    if [[ ! -f /etc/nftables.d/chnroutes.nft ]]; then
        echo "# placeholder — populated by /usr/local/sbin/update-chnroutes" \
            > /etc/nftables.d/chnroutes.nft
    fi

cat <<'UPD_EOF' > /usr/local/sbin/update-chnroutes
#!/usr/bin/env bash
# Refresh /etc/nftables.d/chnroutes.nft with the latest CN CIDR list,
# then atomically reload it into the live `inet xray.cn_ipv4` set.
# Source: misakaio/chnroutes2 (BGP-derived, hourly upstream refresh).
set -euo pipefail

URLS=(
    "https://gh-proxy.com/https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
    "https://gh.ddlc.top/https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
    "https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
)

OUT=/etc/nftables.d/chnroutes.nft
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetched=
for url in "${URLS[@]}"; do
    if curl -fsSL --connect-timeout 8 --max-time 60 "$url" -o "$TMP/raw.txt"; then
        echo "[update-chnroutes] fetched: $url" >&2
        fetched=1
        break
    fi
    echo "[update-chnroutes] failed: $url" >&2
done
[[ "$fetched" ]] || { echo "[update-chnroutes] all mirrors failed" >&2; exit 1; }

# Strip comments + empty lines.
grep -Ev '^$|^#' "$TMP/raw.txt" > "$TMP/cidrs.txt"

count=$(wc -l < "$TMP/cidrs.txt")
if [[ "$count" -lt 1000 ]]; then
    echo "[update-chnroutes] sanity fail: only $count CIDRs (expected >=1000)" >&2
    exit 1
fi

# Build the include file: flush the existing set, then bulk-add the new
# CIDRs. nft applies the file as a single transaction → atomic update.
{
    echo "# Auto-generated by /usr/local/sbin/update-chnroutes"
    echo "# Source: misakaio/chnroutes2 — refreshed $(date -u +%FT%TZ)"
    echo "flush set inet xray cn_ipv4"
    echo "add element inet xray cn_ipv4 { $(paste -sd, "$TMP/cidrs.txt") }"
} > "$OUT.new"
mv "$OUT.new" "$OUT"

# Apply atomically without disturbing other rules in the table.
if ! nft -f "$OUT" 2> "$TMP/nft.err"; then
    cat "$TMP/nft.err" >&2
    exit 1
fi

echo "[update-chnroutes] loaded $count CIDRs into inet xray.cn_ipv4" >&2
UPD_EOF
    chmod +x /usr/local/sbin/update-chnroutes

    mkdir -p /etc/cron.weekly
cat <<'CRON_EOF' > /etc/cron.weekly/update-chnroutes
#!/bin/sh
# Refresh CN routes; output goes to syslog/journal.
exec /usr/local/sbin/update-chnroutes
CRON_EOF
    chmod +x /etc/cron.weekly/update-chnroutes
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

# BBR + fq is the loss-tolerant alternative to CUBIC, and it matters a
# lot in this setup: the Reality tunnel is a single TCP connection
# carrying ALL proxied traffic, so every segment loss head-of-line
# stalls the whole tunnel for ~1 RTT. CN↔overseas paths routinely run
# 0.3–1% loss at peak — CUBIC's throughput collapses to a few Mbps in
# that range, BBR holds ~20+ Mbps. fq qdisc gives BBR proper packet
# pacing (recommended pairing per the BBR authors). Both endpoints of
# the Reality tunnel benefit, so it runs on server and client alike.
# Linux ≥ 4.9 ships BBR; Ubuntu 24.04+ has it auto-loadable.
enable_bbr() {
cat <<'EOF' > /etc/sysctl.d/99-bbr.conf
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
    sysctl --system >/dev/null
    # If the kernel doesn't have BBR available, the sysctl set silently
    # falls back to whatever was active. Verify so the user isn't quietly
    # left on CUBIC, expecting BBR's loss-tolerance behavior.
    local active
    active=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ "$active" != "bbr" ]]; then
        echo -e "[${yellow}Warn${plain}] tcp_congestion_control is '${active}', not 'bbr' — kernel may lack BBR."
        echo -e "[${yellow}Warn${plain}] Tunnel will work but throughput will sag under packet loss."
    fi
}

# Hysteria2 over QUIC needs large UDP socket buffers — kernel defaults
# (~200KB) cap throughput at ~50 Mbps regardless of link speed because
# the QUIC fast-recovery window can't grow large enough. 16MB is the
# value the hy2 docs recommend for 100Mbps+ links. Server-only: the
# client side here uses TCP (Reality), not UDP.
# Source: https://v2.hysteria.network/docs/advanced/Performance-Optimization/
tune_udp_buffers() {
cat <<'EOF' > /etc/sysctl.d/99-udp-buffers.conf
net.core.rmem_max=16777216
net.core.wmem_max=16777216
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
apt install -y curl ca-certificates openssl tar nftables iproute2 unzip cron

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

    chown -R sing-box:sing-box /etc/sing-box

    echo "------ Enabling IP forwarding"
    enable_ip_forward

    echo "------ Tuning UDP socket buffers (for hysteria2)"
    tune_udp_buffers

    echo "------ Enabling BBR congestion control"
    enable_bbr

    echo "------ Writing /etc/nftables.conf (hy2 port-hop ${hy2_port_hop_start}-${hy2_port_hop_end} -> 443)"
    nftables_configure_server_hy2_hop

    echo "------ Starting nftables"
    systemctl enable nftables 2>/dev/null || true
    systemctl restart nftables

    echo "------ Creating sing-box.service"
    create_singbox_service

    echo "------ Starting sing-box"
    systemctl restart sing-box.service

    sleep 2
    if ! systemctl is-active --quiet sing-box; then
        echo -e "[${red}Error${plain}] sing-box failed to start. Check: ${yellow}journalctl -u sing-box -n 50${plain}"
        exit 1
    fi
    if ! systemctl is-active --quiet nftables; then
        echo -e "[${red}Error${plain}] nftables failed to start. Check: ${yellow}journalctl -u nftables -n 50${plain}"
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
        install_xray
    fi

    echo "------ Writing /usr/local/etc/xray/config.json (client)"
    write_xray_client_config "${server_ip}" "${reality_uuid}" "${reality_pubkey}" "${reality_shortid}" "${reality_sni}" "${reality_spiderx}"

    echo "------ Writing /etc/nftables.conf (TPROXY rules)"
    write_tproxy_nftables

    echo "------ Installing chnroutes updater + weekly cron"
    write_chnroutes_assets

    echo "------ Writing tproxy-route.service (policy routing for fwmark 0x1)"
    write_tproxy_route_service

    echo "------ Writing /etc/systemd/system/xray.service"
    create_xray_service

    echo "------ Enabling IP forwarding"
    enable_ip_forward

    echo "------ Enabling BBR congestion control"
    enable_bbr

    echo "------ Starting nftables / tproxy-route / xray"
    systemctl enable nftables 2>/dev/null || true
    systemctl restart nftables
    systemctl restart tproxy-route.service
    systemctl restart xray.service

    echo "------ Populating chnroutes (initial fetch)"
    if /usr/local/sbin/update-chnroutes; then
        echo -e "[${green}OK${plain}] chnroutes loaded; CN traffic will bypass the proxy."
    else
        echo -e "[${yellow}Warn${plain}] chnroutes initial fetch failed — gateway works without CN bypass."
        echo -e "[${yellow}Warn${plain}] Weekly cron will retry; manual: ${yellow}sudo /usr/local/sbin/update-chnroutes${plain}"
    fi

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
    echo -e "${green}Hysteria2 (UDP/443, port-hopping ${hy2_port_hop_start}-${hy2_port_hop_end})${plain} — UDP fallback for QUIC-loving clients:"
    echo -e "  Address          : ${red} $(get_ip) ${plain}"
    echo -e "  Port (single)    : ${red} 443 ${plain}"
    echo -e "  Port-hop range   : ${red} ${hy2_port_hop_start}-${hy2_port_hop_end} ${plain}  (client format: ${yellow}server:443,${hy2_port_hop_start}-${hy2_port_hop_end}${plain})"
    echo -e "  Password         : ${red} ${hy2_password} ${plain}"
    echo -e "  Salamander obfs  : ${red} ${hy2_obfs} ${plain}"
    echo -e "  TLS              : ${red} self-signed (client uses insecure=true) ${plain}"
    echo
    echo -e "${red}Save the values above — the client install will ask for all of them.${plain}"
    echo
    echo -e "${yellow}Cloud provider security group / external firewall — open these:${plain}"
    echo -e "  ${yellow}TCP/443${plain}                     (Reality)"
    echo -e "  ${yellow}UDP/443${plain}                     (hy2 primary)"
    echo -e "  ${yellow}UDP/${hy2_port_hop_start}-${hy2_port_hop_end}${plain}             (hy2 port-hop range)"
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

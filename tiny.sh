#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Two-mode VPN install script. sing-box on both sides.
#
# Server (mode 1): sing-box with two inbounds:
#                    * vless+reality        on TCP/443  (primary, max stealth)
#                    * hysteria2+salamander on UDP/443  (UDP fallback,
#                                                        with port hopping)
#
# Client (mode 2): sing-box with a TUN inbound + vless+reality outbound,
#                  as a transparent gateway for LAN devices.
#                  Routing/CN-bypass live inside sing-box (route rules +
#                  local geoip-cn rule_set), no nftables required.
#                  Client uses Reality TCP only; the server's hy2 inbound
#                  is for external mobile/desktop clients that prefer UDP.
#
# Flow choice (same string on both sides — sing-box does the right thing):
#   * Server inbound:  "xtls-rprx-vision"
#   * Client outbound: "xtls-rprx-vision"
#
# In xray, plain "xtls-rprx-vision" rejects UDP/443 client-side because
# QUIC-over-Vision is double-TLS, so xray defines a separate
# "xtls-rprx-vision-udp443" variant that flips allowUDP443=true and
# strips the suffix before the value hits the wire. sing-box's
# "xtls-rprx-vision" implementation has *no* port-443 UDP guard at all —
# it behaves like xray's -udp443 variant by default. So a transparent
# gateway that can't disable QUIC per-LAN-device just uses the plain
# value. Sources:
#   * sing-box vision impl (no 443 filter): https://raw.githubusercontent.com/sagernet/sing-vmess/main/vless/vision.go
#   * sing-box issue #587 (confirms UDP/443 not blocked): https://github.com/SagerNet/sing-box/issues/587
#   * nekoray issue #898 (cross-impl equivalence note): https://github.com/MatsuriDayo/nekoray/issues/898
#   * xray Vision (for contrast): https://github.com/XTLS/Xray-core/blob/main/proxy/vless/outbound/outbound.go
#
# Client architecture references:
#   * TUN inbound:        https://sing-box.sagernet.org/configuration/inbound/tun/
#   * Route + rule_set:   https://sing-box.sagernet.org/configuration/route/
#   * 1.12+ rule actions: https://sing-box.sagernet.org/migration/
#   * VLESS+Reality out:  https://sing-box.sagernet.org/configuration/outbound/vless/
#   * geoip-cn rule_set:  https://github.com/SagerNet/sing-geoip
#
# System Required: Ubuntu 26.04
#
# Important:
# This script is for learning bash operations.

# --- pinned versions / URLs ------------------------------------------------

# Both sides use sing-box. Bump as needed: https://github.com/SagerNet/sing-box/releases
singbox_version="1.13.11"

# Server-side download URL. The server is overseas and has direct GitHub
# access; no mirror chain needed here. Two %s slots: version, version.
singbox_url_gh="https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-amd64.tar.gz"

# Client-side mirror chain. Client is typically inside CN where direct
# GitHub is rate-limited / RST'd, so we try CN-friendly proxies first
# and fall back to direct GitHub last. Three %s slots: version (URL
# path), version (tarball name), arch ("amd64" or "arm64"). Same
# mirror pattern as the (now-removed) xray client install — those
# proxies front any github.com URL, the path is opaque to them.
#
# If you find a better mirror or one of these dies, prepend/swap freely.
# Manual escape hatch is documented in install_singbox_client() below.
singbox_client_url_templates=(
    "https://gh-proxy.com/https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz"
    "https://ghfast.top/https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz"
    "https://kkgithub.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz"
    "https://gh.ddlc.top/https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz"
    "https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz"
)

# Hysteria2 port-hopping range (server side). The hy2 socket binds only
# to UDP/443; an nftables NAT redirect maps this whole UDP range onto
# UDP/443 so clients can rotate ports to defeat per-port ISP throttling
# (China Telecom 163 backbone caps unclassified UDP flows at ~1 Mbps
# after sustained use of a single port). Range is wide on purpose —
# narrow ranges are themselves a fingerprint.
# Source: https://v2.hysteria.network/docs/advanced/Port-Hopping/
hy2_port_hop_start=20000
hy2_port_hop_end=50000

# CN-route bypass is handled in-config via remote rule_sets pulled from
# MetaCubeX/meta-rules-dat (see route.rule_set in write_singbox_client_config).
# sing-box fetches and refreshes those on its own schedule, so the script
# no longer needs a local .srs file or weekly cron.

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

# --- client-only helpers (sing-box + TUN) ---------------------------------

# Tries each entry of singbox_client_url_templates in order, first success
# wins. install_singbox_from() is shared with the server side — it's the
# tarball-fetch primitive; this function just adds CN-friendly mirror
# fallback and arch detection on top.
#
# Manual escape hatch — if all mirrors fail in your network:
#   1. From any machine with working GitHub access (e.g. your overseas
#      server), download and copy the tarball to the gateway:
#        wget https://github.com/SagerNet/sing-box/releases/download/v${singbox_version}/sing-box-${singbox_version}-linux-amd64.tar.gz
#        scp sing-box-${singbox_version}-linux-amd64.tar.gz gateway:/tmp/
#   2. On the gateway: pre-place the binary so this script's `command -v
#      sing-box` check short-circuits the download:
#        sudo tar -xzf /tmp/sing-box-*.tar.gz -C /tmp/ --strip-components=1
#        sudo install -m 755 /tmp/sing-box /usr/local/bin/sing-box
#   3. Re-run sudo ./tiny.sh — install will be skipped entirely.
install_singbox_client() {
    local v="${singbox_version}"
    local arch
    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) exception "Unsupported architecture for sing-box: $(uname -m)" ;;
    esac
    local tmpl url
    for tmpl in "${singbox_client_url_templates[@]}"; do
        url=$(printf "${tmpl}" "$v" "$v" "$arch")
        echo "------ Trying: ${url}"
        if install_singbox_from "$url"; then
            echo "[${green}OK${plain}] sing-box ${v} installed."
            return 0
        fi
        echo "[${yellow}Warn${plain}] Failed; trying next mirror..."
    done
    exception "All sing-box mirrors failed. See manual escape hatch in install_singbox_client() comment in tiny.sh."
}

# Same systemd unit as the server, just retagged. Runs as the sing-box
# system user; CAP_NET_ADMIN is required by the TUN inbound (open
# /dev/net/tun, install routes, set up auto_route's ip rules).
# Source: https://sing-box.sagernet.org/installation/package-manager/#systemd
create_singbox_client_service() {
cat <<'SVC_EOF' > /etc/systemd/system/sing-box.service
[Unit]
Description=sing-box service (client)
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

# Client config — written against the sing-box 1.13.x schema. TUN inbound
# captures all LAN-forwarded traffic; auto_route + auto_redirect +
# auto_detect_interface together install policy routes (auto_route) +
# nftables redirect rules (auto_redirect, "better than tproxy" per
# upstream) + bind sing-box's own outbound sockets to the physical NIC
# (auto_detect_interface, the equivalent of xray's `sockopt.mark = 0xff`
# for loop avoidance).
#
# DNS architecture (split-horizon + fakeip):
#   * proxy_dns  — DoH to dns.google via `detour: "proxy"`. Handles non-A/AAAA
#                  queries (TXT/MX/etc.) and is the `final` server.
#                  `domain_resolver: "cn_dns"` is required because the server
#                  field is a hostname (sing-box resolves it once at startup).
#   * cn_dns     — type "local": delegates to the gateway OS's resolver
#                  (systemd-resolved on Ubuntu 26.04). Used to resolve CN sites
#                  so they get region-local CDN edges. Loop-safe under TUN DNS
#                  hijack because "local" uses systemd-resolved's D-Bus interface
#                  on Linux, not UDP/53.
#   * fakeip     — synthetic IP allocator (198.18.0.0/15 / fc00::/18). Returns
#                  a deterministic fake IP for every proxied A/AAAA query. When
#                  the LAN client connects to that fake IP, sing-box's router
#                  detects the fakeip-range destination and rewrites
#                  metadata.Destination.Fqdn back to the original hostname
#                  BEFORE the outbound dial — so the overseas server receives
#                  "connect to <hostname>" and resolves it from its own clean
#                  DNS. This is the sing-box equivalent of xray's
#                  `sniffing.destOverride + routeOnly:false` (see master branch).
#
# Why fakeip and not plain `sniff`: sing-box 1.13.0 removed the legacy
# `sniff_override_destination` inbound field, and the route-rule `sniff` action
# does not expose an equivalent option in JSON. Sniff still populates
# `metadata.Domain` for routing decisions, but does NOT rewrite the outbound
# destination. Without fakeip the gateway forwards the LAN-resolved (often
# GFW-poisoned) IP to the server, which then times out dialing it. Sources:
#   * route.go fakeip reverse-mapping:
#       https://github.com/SagerNet/sing-box/blob/v1.13.11/route/route.go
#   * RuleActionSniff — OverrideDestination is marked Deprecated and no longer
#     reachable from JSON config:
#       https://github.com/SagerNet/sing-box/blob/v1.13.11/route/rule/rule_action.go
#   * fakeip server schema:
#       https://sing-box.sagernet.org/configuration/dns/server/fakeip/
#
# Hard requirement: LAN clients MUST use this gateway as their DNS server,
# otherwise they bypass fakeip entirely. Force it via DHCP option 6 on the
# LAN router (advertise this gateway's LAN IP as the only DNS server). LAN
# devices that ignore DHCP DNS (Chrome auto-DoH, iOS/Android Private DNS
# pointed at an external DoT endpoint, hard-coded resolvers like Chromecast
# / smart-TV sticks, etc.) will still leak — block known DoH/DoT endpoints
# with additional route rules if you have such devices.
#
# Upstream tracking — both constraints above (needing fakeip at all, AND
# needing to force gateway-as-DNS for every LAN device) would disappear if
# sing-box restored any mechanism to set metadata.Destination from the
# sniffed domain. Two plausible paths that would lift it:
#   * Expose the (currently-deprecated, hidden-from-JSON) `OverrideDestination`
#     field of the route-rule `sniff` action — this is what the master
#     branch's xray client already does via `sniffing.routeOnly: false`.
#   * Add a new `route-options` flag (e.g. `use_sniffed_domain: true`) that
#     copies metadata.Domain into metadata.Destination.Fqdn post-sniff.
#
# Upstream has so far rejected requests to restore the legacy
# `sniff_override_destination` field — see SagerNet/sing-box issues
# #3982, #3951, #4011, all closed "completed" with fakeip pointed at as
# the canonical workaround. Re-check those (and any successor) on each
# sing-box bump; if either mechanism above lands, the fakeip server,
# the A/AAAA→fakeip DNS rule, AND the LAN-must-use-gateway-DNS
# requirement can all be dropped.
#
# CN sites are exempted from fakeip via the rule_set=cnsite DNS rule
# (matched FIRST, before the A/AAAA→fakeip catch-all), so they keep real
# CN-edge IPs and bypass the proxy via the cnip/cnsite route rules.
#
# dns_mode is the default ("hijack"): the route rule
# `{ "protocol": "dns", "action": "hijack-dns" }` catches UDP/53 packets from
# LAN clients (to any upstream) and routes them into the DNS module above.
# Source: https://sing-box.sagernet.org/configuration/inbound/tun/#dns_mode
#
# rule_sets are fetched remotely from MetaCubeX/meta-rules-dat (the most
# actively-maintained sing-box rule_set repo), refreshed every 24h via
# `update_interval`. Initial fetch happens after sing-box starts, so on
# first boot all traffic falls through to `final: "proxy"` until those
# downloads complete (~30s). `download_detour: "proxy"` routes the fetches
# through the tunnel — important because raw.githubusercontent.com isn't
# reachable from inside the GFW.
#
# Refs:
#   * TUN options:        https://sing-box.sagernet.org/configuration/inbound/tun/
#   * Route + rule_set:   https://sing-box.sagernet.org/configuration/route/
#   * DNS local server:   https://sing-box.sagernet.org/configuration/dns/server/local/
#   * DNS https server:   https://sing-box.sagernet.org/configuration/dns/server/https/
#   * VLESS+Reality out:  https://sing-box.sagernet.org/configuration/outbound/vless/
#   * Rule sets source:   https://github.com/MetaCubeX/meta-rules-dat
#
# Note on `flow`: sing-box's "xtls-rprx-vision" has no UDP/443 guard, so
# it works as the gateway's outbound flow without the xray-specific
# "-udp443" suffix. See header notes (top of this file) for sources.
write_singbox_client_config() {
    local server_ip="$1" uuid="$2" pubkey="$3" sid="$4" sni="$5"
cat <<'CFG_EOF' > /etc/sing-box/config.json
{
  "log": { "level": "warn", "timestamp": true },
  "dns": {
    "servers": [
      {
        "tag": "proxy_dns",
        "type": "https",
        "server": "dns.google",
        "domain_resolver": "cn_dns",
        "detour": "proxy"
      },
      {
        "tag": "cn_dns",
        "type": "local"
      },
      {
        "tag": "fakeip",
        "type": "fakeip",
        "inet4_range": "198.18.0.0/15",
        "inet6_range": "fc00::/18"
      }
    ],
    "rules": [
      { "rule_set": "cnsite", "server": "cn_dns" },
      { "query_type": ["A", "AAAA"], "server": "fakeip" }
    ],
    "final": "proxy_dns",
    "independent_cache": true
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "singtun0",
      "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "mtu": 1500,
      "auto_route": true,
      "auto_redirect": true,
      "strict_route": true,
      "stack": "system"
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "proxy",
      "server": "___SERVER_IP___",
      "server_port": 443,
      "uuid": "___UUID___",
      "flow": "xtls-rprx-vision",
      "packet_encoding": "xudp",
      "tls": {
        "enabled": true,
        "server_name": "___SNI___",
        "utls": { "enabled": true, "fingerprint": "chrome" },
        "reality": {
          "enabled": true,
          "public_key": "___PUBKEY___",
          "short_id": "___SID___"
        }
      }
    },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "cn_dns",
    "rule_set": [
      {
        "tag": "cnsite",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geosite/cn.srs",
        "update_interval": "24h",
        "download_detour": "proxy"
      },
      {
        "tag": "cnip",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geoip/cn.srs",
        "update_interval": "24h",
        "download_detour": "proxy"
      },
      {
        "tag": "cngames",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geosite/category-games-!cn@cn.srs",
        "update_interval": "24h",
        "download_detour": "proxy"
      },
      {
        "tag": "gfw",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geosite/gfw.srs",
        "update_interval": "24h",
        "download_detour": "proxy"
      }
    ],
    "rules": [
      { "action": "sniff" },
      { "protocol": "dns", "action": "hijack-dns" },
      { "network": "icmp", "outbound": "direct" },
      { "ip_is_private": true, "outbound": "direct" },
      { "rule_set": "gfw", "outbound": "proxy" },
      { "rule_set": "cnsite", "outbound": "direct" },
      { "rule_set": "cnip", "outbound": "direct" },
      { "rule_set": "cngames", "outbound": "direct" }
    ],
    "final": "proxy"
  }
}
CFG_EOF
    sed -i \
        -e "s|___SERVER_IP___|${server_ip}|g" \
        -e "s|___UUID___|${uuid}|g" \
        -e "s|___PUBKEY___|${pubkey}|g" \
        -e "s|___SID___|${sid}|g" \
        -e "s|___SNI___|${sni}|g" \
        /etc/sing-box/config.json
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
# Server needs nftables (hy2 port-hop NAT) + openssl (self-signed cert).
# Client needs nftables (auto_redirect uses it) + iproute2 (auto_route hooks).
# curl/ca-certificates/tar are common to both (singbox tarball download).
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
    # All Reality values come from the server install printout — they
    # must match the server's vless+reality inbound exactly.
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

    # Note: xray had an extra "spiderX" parameter here; sing-box's reality
    # outbound does not expose it (the path is fixed inside sing-vmess).

    ensure_singbox_user
    mkdir -p /etc/sing-box

    if ! command -v sing-box >/dev/null 2>&1; then
        echo "------ Installing sing-box ${singbox_version} (trying CN-friendly mirrors first)"
        install_singbox_client
    fi

    echo "------ Writing /etc/sing-box/config.json (client)"
    write_singbox_client_config "${server_ip}" "${reality_uuid}" "${reality_pubkey}" "${reality_shortid}" "${reality_sni}"

    # Note: rule_sets (CN bypass, GFW list, etc.) are remote and fetched by
    # sing-box itself on its own schedule (update_interval in config.json).
    # On first boot, traffic falls through to `final: "proxy"` until those
    # downloads complete (typically <30s); no local pre-fetch needed.

    echo "------ Writing /etc/systemd/system/sing-box.service"
    create_singbox_client_service

    echo "------ Enabling IP forwarding"
    enable_ip_forward

    echo "------ Enabling BBR congestion control"
    enable_bbr

    echo "------ Starting sing-box"
    systemctl restart sing-box.service

    sleep 2
    if ! systemctl is-active --quiet sing-box; then
        echo -e "[${red}Error${plain}] sing-box failed to start. Check: ${yellow}journalctl -u sing-box -n 50${plain}"
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
    echo -e "${red}CRITICAL${plain}: LAN clients MUST use this gateway as their ${red}DNS server${plain} too"
    echo -e "(DHCP option 6 → gateway LAN IP). The fakeip mechanism that lets the"
    echo -e "overseas server resolve hostnames itself only fires for DNS queries that"
    echo -e "hit this sing-box instance — devices that use external DoH/DoT (Chrome"
    echo -e "auto-DoH, iOS Private Relay, Android Private DNS) will bypass it and"
    echo -e "fail with i/o-timeout on GFW-poisoned or geo-restricted destinations."
    echo
    echo -e "Health checks:"
    echo -e "  ${yellow}systemctl status sing-box${plain}"
    echo -e "  ${yellow}journalctl -u sing-box -f${plain}"
    echo -e "  ${yellow}ip link show singtun0${plain}                   # TUN device (auto_route)"
    echo -e "  ${yellow}ip route show table all | grep singtun0${plain} # routes auto-installed by sing-box"
    echo -e "  ${yellow}ls -lh /var/lib/sing-box${plain}                # cached rule_sets (cnsite/cnip/gfw/cngames)"
    echo -e "  From a LAN device pointed at this gateway (gateway + DNS):"
    echo -e "  ${yellow}curl https://ifconfig.me${plain}                # should return the SERVER's IP"
    echo -e "  ${yellow}curl https://www.baidu.com -I${plain}           # should bypass proxy (CN-route)"
    echo -e "  ${yellow}dig @<gateway-LAN-ip> www.google.com${plain}    # should answer in fakeip range (198.18/15)"
fi

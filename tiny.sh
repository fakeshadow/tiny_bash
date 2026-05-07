#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Server/Client script for tinyfecVPN + udp2raw (ICMP mode), with optional
# xray-Reality on TCP/443 for mobile clients (server only).

# System Required: Ubuntu 24.04

# Important:
# This script is for learning bash operations. Please delete all the compiled files after you done with it.

# Credits:
# @Teddysun <i@teddysun.com> for copy paste scripts

# links
tiny_vpn_repo="https://github.com/wangyu-/tinyfecVPN.git"
udp2raw_repo="https://github.com/wangyu-/udp2raw-tunnel.git"
chnroutes_url="https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
xray_install_url="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"

# udp2raw uses port numbers as internal multiplexing tags in icmp mode; not on the wire.
udp2raw_port=4096
# tinyvpn tun device name; same on both sides for nftables references.
tun_dev="tun100"

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

detect_wan_iface() {
    ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1
}

enable_ip_forward() {
cat <<'EOF' > /etc/sysctl.d/99-vpn.conf
net.ipv4.ip_forward=1
EOF
sysctl --system >/dev/null
}

enable_icmp_ignore() {
cat <<'EOF' > /etc/sysctl.d/99-udp2raw-icmp.conf
# udp2raw uses ICMP raw sockets in --raw-mode icmp. Stop the kernel from
# auto-replying to pings, otherwise its replies fight with udp2raw's own.
# Side effect: server can no longer be pinged from anywhere — use TCP-based
# liveness checks instead.
net.ipv4.icmp_echo_ignore_all=1
EOF
sysctl --system >/dev/null
}

configure_dns() {
mkdir -p /etc/systemd/resolved.conf.d
cat <<'EOF' > /etc/systemd/resolved.conf.d/dot.conf
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
FallbackDNS=9.9.9.9#dns.quad9.net
DNSOverTLS=yes
DNSSEC=allow-downgrade
Cache=yes
EOF
systemctl restart systemd-resolved
}

create_service() {
local exec="$1"
local name="$2"
local deps="$3"  # optional space-separated unit list
local after="network-online.target"
local requires=""
if [[ -n "$deps" ]]; then
    after="${after} ${deps}"
    requires="Requires=${deps}"
fi
cat <<EOF > /etc/systemd/system/${name}.service
[Unit]
Wants=network-online.target
After=${after}
${requires}

[Service]
ExecStart=${exec}
Restart=always

[Install]
WantedBy=multi-user.target
EOF
systemctl enable ${name}.service
}

create_chnroutes_cron() {
mkdir -p /etc/nftables.d
# Placeholder so the include in /etc/nftables.conf parses on first boot.
[[ -f /etc/nftables.d/chnroutes.nft ]] || echo "# populated by /etc/cron.weekly/chnroutes" > /etc/nftables.d/chnroutes.nft

cat <<EOF > /etc/cron.weekly/chnroutes
#!/usr/bin/env bash
set -e

URL="${chnroutes_url}"
OUTPUT="/etc/nftables.d/chnroutes.nft"
TMP=\$(mktemp)
trap 'rm -f "\$TMP"' EXIT

curl -sL "\$URL" | grep -Ev '^\$|^#' > "\$TMP"

if [[ ! -s "\$TMP" ]] || [[ \$(wc -l < "\$TMP") -lt 1000 ]]; then
    echo "chnroutes download looks bad, aborting" >&2
    exit 1
fi

{
    echo "add element inet vpngw chnroutes {"
    paste -sd, "\$TMP"
    echo "}"
} > "\$OUTPUT.new"

mv "\$OUTPUT.new" "\$OUTPUT"
nft -f /etc/nftables.conf
EOF
chmod +x /etc/cron.weekly/chnroutes
}

nftables_configure_client() {
local server_ip="$1"
cat <<EOF > /etc/nftables.conf
#!/usr/sbin/nft -f

# Idempotent: declare-then-flush so re-runs replace cleanly without affecting
# any other tables.
add table inet vpngw
flush table inet vpngw

table inet vpngw {
    set chnroutes {
        type ipv4_addr
        flags interval
    }

    set bypass4 {
        type ipv4_addr
        flags interval
        elements = {
            0.0.0.0/8,
            10.0.0.0/8,
            127.0.0.0/8,
            169.254.0.0/16,
            172.16.0.0/12,
            192.168.0.0/16,
            224.0.0.0/4,
            240.0.0.0/4,
            ${server_ip}/32
        }
    }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        ip daddr @bypass4 return
        ip daddr @chnroutes return
        meta mark set 0x1
    }

    chain output {
        type filter hook output priority mangle; policy accept;
        ip daddr @bypass4 return
        ip daddr @chnroutes return
        meta mark set 0x1
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "${tun_dev}" masquerade
    }

    chain input {
        type filter hook input priority filter; policy accept;
        # udp2raw handles ICMP echo replies via raw sockets. Drop kernel-visible
        # copies from the server only, so the box can still ping other hosts.
        ip saddr ${server_ip} icmp type echo-reply drop
    }
}

include "/etc/nftables.d/chnroutes.nft"
EOF
}

nftables_configure_server() {
local subnet="$1"
local wan_iface
wan_iface=$(detect_wan_iface)
[[ -z "$wan_iface" ]] && exception "Could not detect WAN interface"

local server_ip
server_ip=$(get_ip)

cat <<EOF > /etc/nftables.conf
#!/usr/sbin/nft -f

# Don't flush the global ruleset — coexist with xray-Reality and any other
# services that may install rules dynamically.
add table inet vpngw
flush table inet vpngw

table inet vpngw {
    chain forward {
        type filter hook forward priority filter; policy accept;
        # Anti-abuse: tunnel users can't reach the server's private nets,
        # loopback, or back into the server's own public IP.
        iifname "${tun_dev}" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16 } drop
        iifname "${tun_dev}" ip daddr ${server_ip} drop
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "${wan_iface}" ip saddr ${subnet}/24 masquerade
    }
}
EOF
}

install_xray_reality() {
local server_name="$1"
[[ -z "$server_name" ]] && server_name="www.cloudflare.com"

echo "------ Installing xray-core"
bash -c "$(curl -L ${xray_install_url})" @ install

echo "------ Generating Reality keys & config"
local uuid pubkey privkey shortid keys_out
uuid=$(xray uuid)
keys_out=$(xray x25519)
# xray output formats vary across versions: "Private key:" / "PrivateKey:"
# and "Public key:" / "Password:" (newer). Match either.
privkey=$(echo "$keys_out" | grep -E '^[Pp]rivate ?[Kk]ey' | head -1 | awk -F': *' '{print $2}')
pubkey=$(echo "$keys_out"  | grep -E '^[Pp]ublic ?[Kk]ey|^Password' | head -1 | awk -F': *' '{print $2}')
shortid=$(openssl rand -hex 8)

cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${uuid}", "flow": "xtls-rprx-vision" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${server_name}:443",
          "xver": 0,
          "serverNames": ["${server_name}"],
          "privateKey": "${privkey}",
          "shortIds": ["", "${shortid}"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" }
  ]
}
EOF

systemctl restart xray

# Stash for the summary block.
REALITY_UUID="$uuid"
REALITY_PUBKEY="$pubkey"
REALITY_SHORTID="$shortid"
REALITY_SERVERNAME="$server_name"
}

[[ $EUID -ne 0 ]] && exception "This script must be run as root!"

echo "------ Choose your platform"
read -p "[1: Server, 2: Client]: " platform
[[ -z "${platform}" ]] && exception "Must choose your platform!"

if [[ "${platform}" != "1"  ]] &&  [[ "${platform}" != "2"  ]] ; then
        exception "Platform must be ${yellow}1${plain}(Server) or ${yellow}2${plain}(Client)!"
fi

echo "------ Install dependencies"
apt update
apt install -y git build-essential nftables curl

echo "------ Downloading repos"
git clone --recursive ${tiny_vpn_repo} /root/tinyvpn
git clone ${udp2raw_repo} /root/udp2raw

echo "------ Compiling repos"
cd /root/tinyvpn
make -f makefile amd64
mkdir -p /usr/local/tinyvpn
mv tinyvpn_amd64 /usr/local/tinyvpn/tinyvpn_amd64

cd /root/udp2raw
make
mkdir -p /usr/local/udp2raw
mv udp2raw /usr/local/udp2raw/udp2raw

if [[ "${platform}" == "2" ]]; then
    echo "------ Configuring the installation"
    echo "Enter your Server IP"
    read -p ": " server_ip
    [[ -z "${server_ip}" ]] && exception "Server IP must be set!"
fi

echo "Enter tinyfecVPN sub net"
read -p "Default(10.22.22.0): " subnet
[[ -z "${subnet}" ]] && subnet="10.22.22.0"

echo "Enter your fec setting"
read -p "Default(20:10): " fec
[[ -z "${fec}" ]] && fec="20:10"

echo "Enter your udp2raw/tinyfecVPN password"
read -p "Default(1234): " password
[[ -z "${password}" ]] && password="1234"

if [[ "${platform}" == "1" ]]; then
    echo "Install xray + Reality on TCP/443? [Y/n]"
    read -p "Default(Y): " install_reality
    install_reality="${install_reality:-Y}"
    if [[ "${install_reality}" =~ ^[Yy]$ ]]; then
        echo "Reality serverName (a real TLS site to mimic)"
        read -p "Default(www.cloudflare.com): " reality_dest
        reality_dest="${reality_dest:-www.cloudflare.com}"
    fi
fi

echo "------ Generating run scripts"
mkdir -p /etc/tinyvpn /etc/udp2raw

if [[ "${platform}" == "1" ]]; then
cat > /etc/tinyvpn/tinyvpn.sh <<EOF
#!/usr/bin/env bash
exec /usr/local/tinyvpn/tinyvpn_amd64 -s -l0.0.0.0:14096 -f ${fec} --sub-net ${subnet} --tun-dev ${tun_dev} -k ${password}
EOF
cat > /etc/udp2raw/udp2raw.sh <<EOF
#!/usr/bin/env bash
exec /usr/local/udp2raw/udp2raw -s -l0.0.0.0:${udp2raw_port} -r127.0.0.1:14096 --raw-mode icmp -k ${password}
EOF
elif [[ "${platform}" == "2" ]]; then
cat > /etc/tinyvpn/tinyvpn.sh <<EOF
#!/usr/bin/env bash
# Set up policy routing once tun100 appears. Re-runs harmlessly on tinyvpn restart
# (rule/route adds error if already present, swallowed by '|| true').
(
    while ! ip link show ${tun_dev} >/dev/null 2>&1; do sleep 0.5; done
    ip rule add fwmark 0x1/0x1 table 100 2>/dev/null || true
    ip route add default dev ${tun_dev} table 100 2>/dev/null || true
) &
exec /usr/local/tinyvpn/tinyvpn_amd64 -c -r127.0.0.1:14096 -f ${fec} --sub-net ${subnet} --tun-dev ${tun_dev} --keep-reconnect -k ${password}
EOF
cat > /etc/udp2raw/udp2raw.sh <<EOF
#!/usr/bin/env bash
exec /usr/local/udp2raw/udp2raw -c -r${server_ip}:${udp2raw_port} -l127.0.0.1:14096 --raw-mode icmp -k ${password}
EOF
fi

chmod +x /etc/tinyvpn/tinyvpn.sh
chmod +x /etc/udp2raw/udp2raw.sh

echo "------ Configuring services"
if [[ "${platform}" == "1" ]]; then
    # Server: tinyvpn must listen on :14096 before udp2raw forwards there.
    create_service "/etc/tinyvpn/tinyvpn.sh" "tinyvpn"
    create_service "/etc/udp2raw/udp2raw.sh" "udp2raw" "tinyvpn.service"
elif [[ "${platform}" == "2" ]]; then
    # Client: udp2raw is egress; tinyvpn rides on top via 127.0.0.1:14096.
    create_service "/etc/udp2raw/udp2raw.sh" "udp2raw"
    create_service "/etc/tinyvpn/tinyvpn.sh" "tinyvpn" "udp2raw.service"
fi

echo "------ Enabling IP forwarding"
enable_ip_forward

if [[ "${platform}" == "1" ]]; then
    echo "------ Disabling kernel ICMP echo replies"
    enable_icmp_ignore

    echo "------ Configuring nftables"
    nftables_configure_server "${subnet}"
    systemctl enable nftables
    systemctl restart nftables

    if [[ "${install_reality}" =~ ^[Yy]$ ]]; then
        install_xray_reality "${reality_dest}"
    fi
elif [[ "${platform}" == "2" ]]; then
    echo "------ Configuring DNS over TLS"
    configure_dns

    echo "------ Configuring nftables and chnroutes"
    nftables_configure_client "${server_ip}"
    create_chnroutes_cron
    /etc/cron.weekly/chnroutes

    systemctl enable nftables
    systemctl restart nftables
fi

echo "------ Starting services"
if [[ "${platform}" == "1" ]]; then
    # Starting udp2raw pulls in tinyvpn via Requires=
    systemctl start udp2raw.service
elif [[ "${platform}" == "2" ]]; then
    # Starting tinyvpn pulls in udp2raw via Requires=
    systemctl start tinyvpn.service
fi

echo "------ Cleaning up"
rm -rf /root/tinyvpn /root/udp2raw

clear
if [[ "${platform}" == "1" ]]; then
    echo -e "Congratulations, ${green}Server${plain} install completed!"
    echo -e "${red}Copy the info below as you need them in your client script!${plain}"
    echo -e "Your Server IP                    : ${red} $(get_ip) ${plain}"
    echo -e "Your tinyfecVPN sub net           : ${red} ${subnet} ${plain}"
    echo -e "Your tinyfecVPN fec setting       : ${red} ${fec} ${plain}"
    echo -e "Your udp2raw/tinyfecVPN password  : ${red} ${password} ${plain}"
    if [[ "${install_reality}" =~ ^[Yy]$ ]]; then
        echo
        echo -e "${green}xray + Reality${plain} (configure your mobile app):"
        echo -e "  Address       : ${red} $(get_ip) ${plain}"
        echo -e "  Port          : ${red} 443 ${plain}"
        echo -e "  UUID          : ${red} ${REALITY_UUID} ${plain}"
        echo -e "  Flow          : ${red} xtls-rprx-vision ${plain}"
        echo -e "  Public key    : ${red} ${REALITY_PUBKEY} ${plain}"
        echo -e "  Short ID      : ${red} ${REALITY_SHORTID} ${plain}"
        echo -e "  ServerName    : ${red} ${REALITY_SERVERNAME} ${plain}"
        echo -e "  Fingerprint   : ${red} chrome ${plain}"
    fi
elif [[ "${platform}" == "2" ]]; then
    echo -e "Congratulations, ${green}Client${plain} install completed!"
fi

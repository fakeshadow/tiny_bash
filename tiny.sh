#! /bin/sh

# Server/Client script for tinyfecVPN + udp2raw + shadowsocks + overture

# System Required: Ubuntu 20

# Important:
# This script is for learning bash operations. Please delete all the compiled files after you done with it.

# Credits:
# @Teddysun <i@teddysun.com> for copy paste scripts

# links
tiny_vpn_repo=https://github.com/wangyu-/tinyfecVPN.git
udp2raw_repo=https://github.com/wangyu-/udp2raw-tunnel.git
ss_repo=https://github.com/shadowsocks/shadowsocks-libev.git
overture_release=https://github.com/shawn1m/overture/releases/download/v1.6.1/overture-linux-amd64.zip

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

exception() {
    echo -e "[${red}Error${plain}] ${1}" && exit 1
}

get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [[ -z ${IP} ]] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [[ -z ${IP} ]] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    echo ${IP}
}

check_kernel_version(){
    local kernel_version=$(uname -r | cut -d- -f1)
    if version_gt ${kernel_version} 3.7.0; then
        return 0
    else
        return 1
    fi
}

check_kernel_headers(){
    if check_sys packageManager yum; then
        if rpm -qa | grep -q headers-$(uname -r); then
            return 0
        else
            return 1
        fi
    elif check_sys packageManager apt; then
        if dpkg -s linux-headers-$(uname -r) > /dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    fi
    return 1
}

service_template() {
  echo "[Unit]
Wants=network-online.target
After=network-online.target

[Service]
Type=idle
ExecStart=$1
Restart=always

[Install]
WantedBy=basic.target
" >"/etc/systemd/system/${2}.service"
}

iptables_configure() {
    echo "#! /bin/sh
ip rule del fwmark 0x01/0x01 table 100
ip route del local 0.0.0.0/0 dev lo table 100
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
ipset destroy chnroutes
ipset restore < /root/chnroutes.ipset

iptables -t nat -N sstcp
iptables -t nat -A sstcp -d 0.0.0.0/8 -j RETURN
iptables -t nat -A sstcp -d 10.0.0.0/8 -j RETURN
iptables -t nat -A sstcp -d 127.0.0.0/8 -j RETURN
iptables -t nat -A sstcp -d 169.254.0.0/16 -j RETURN
iptables -t nat -A sstcp -d 172.16.0.0/12 -j RETURN
iptables -t nat -A sstcp -d 192.168.0.0/16 -j RETURN
iptables -t nat -A sstcp -d 224.0.0.0/4 -j RETURN
iptables -t nat -A sstcp -d 240.0.0.0/4 -j RETURN

iptables -t nat -A sstcp -d ${1}/32 -j RETURN

iptables -t nat -A sstcp -m set --match-set chnroutes dst -j RETURN
iptables -t nat -A sstcp -p tcp -j REDIRECT --to-ports 1081
iptables -t nat -I PREROUTING -p tcp -j sstcp

ip rule add fwmark 0x01/0x01 table 100
ip route add local 0.0.0.0/0 dev lo table 100
iptables -t mangle -N ssudp
iptables -t mangle -A ssudp -d 0.0.0.0/8 -j RETURN
iptables -t mangle -A ssudp -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A ssudp -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A ssudp -d 169.254.0.0/16 -j RETURN
iptables -t mangle -A ssudp -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A ssudp -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A ssudp -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A ssudp -d 240.0.0.0/4 -j RETURN

iptables -t mangle -A ssudp -d ${1}/32 -j RETURN

iptables -t mangle -A ssudp -d 119.29.29.29/32 -j RETURN
iptables -t mangle -A ssudp -d 114.114.114.114 -j RETURN

iptables -t mangle -A ssudp -m set --match-set chnroutes dst -j RETURN
iptables -t mangle -A ssudp -p udp -j TPROXY --on-port 1081 --tproxy-mark 0x01/0x0
iptables -t mangle -A PREROUTING -p udp -j ssudp" >/root/iptables-config.sh
}

[[ $EUID -ne 0 ]] && exception "This script must be run as root!"

echo "------ Choose your platform"
read -p "[1: Sever, 2: Client]: " platform
[[ -z "${platform}" ]] && exception "Must choose your platform!"

if [[ "${platform}" != "1"  ]] &&  [[ "${platform}" != "2"  ]] ; then
        exception "Platform must be ${yellow}1${plain}(Server) or ${yellow}2${plain}(Client)!"
fi

echo "------ Deleting existing repos"
rm -rf /root/tinyvpn
rm -rf /root/udp2raw
rm -rf /root/ss

echo "------ Install dependencies"
apt install --no-install-recommends git gettext build-essential autoconf libtool libpcre3-dev asciidoc xmlto libev-dev libc-ares-dev automake libmbedtls-dev libsodium-dev -y

if [[ "${platform}" == "2" ]]; then
    rm -rf /root/overture-linux-amd64.zip
    echo "------ Downloading release files"
    wget ${overture_release}
    unzip overture-linux-amd64.zip -d overture
fi

echo "------ Downloading repos"
git clone --recursive ${tiny_vpn_repo} /root/tinyvpn
git clone ${udp2raw_repo} /root/udp2raw
git clone ${ss_repo} /root/ss

echo "------ Compiling repos"
cd /root/tinyvpn
./makefile
cd /root/udp2raw
make
cd /root/ss
git submodule init && git submodule update
./autogen.sh
./configure --prefix=/usr/local/shadowsocks
make
make install

if [[ "${platform}" == "2" ]]; then
    echo "------ Configuring the installation"
    echo "Enter your Server IP"
    read -p ": " ip
    # ToDo: check if ip is valid
    [[ -z "${ip}" ]] && exception "Server IP must be set!"
fi

echo "Enter tinyfecVPN sub net"
read -p "Default(10.22.22.0): " subnet
[[ -z "${subnet}" ]] && subnet="10.22.22.0"

if [[ "${platform}" == "2" ]]; then
    echo "Enter tinyfecVPN dev tunnel"
    read -p "Default(tun100): " tunnel
    [[ -z "${tunnel}" ]] && tunnel="tun100"
fi

echo "Enter your udp2raw port"
read -p "Default(443): " port
[[ -z "${port}" ]] && port=443

echo "Enter your fec setting"
read -p "Default(20:10): " fec
[[ -z "${fec}" ]] && fec="20:10"

echo "Enter your upd2raw/tinyfecVPN password"
read -p "Default(1234): " password
[[ -z "${password}" ]] && password="1234"

echo "Enter your shadowsocks server port"
read -p "Default(16541): " ssport
[[ -z "${ssport}" ]] && ssport="16541"

echo "Enter your shadowsocks password"
read -p "Default(fakeshadow): " sspwd
[[ -z "${sspwd}" ]] && sspwd="fakeshadow"

echo "------ Generating ss config file"
if [[ "${platform}" == "1" ]]; then
    if check_kernel_version && check_kernel_headers; then
        fast_open="true"
    else
        fast_open="false"
    fi
cat >/root/ss-config.json <<-EOF
{
    "server":"0.0.0.0",
    "server_port":${ssport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${sspwd}",
    "timeout":120,
    "method":"rc4-md5",
    "fast_open":${fast_open},
    "workers":1
}
EOF
fi

if [[ "${platform}" == "2" ]]; then
cat >/root/ss-config.json <<-EOF
{
    "server": "${ss_server}.1",
    "server_port": ${ssport},
    "local_address": "0.0.0.0",
    "local_port": 1081,
    "password": "${sspwd}",
    "timeout": 120,
    "method": "rc4-md5",
    "workers": 1
}
EOF
fi

echo "------ Enabling services"
service_template "/root/tinyvpn.sh" "tinyvpn"
systemctl enable tinyvpn.service
service_template "/root/udp2raw.sh" "udp2raw"
systemctl enable udp2raw.service

if [[ "${platform}" == "1" ]]; then
    service_template "/usr/local/shadowsocks/bin/ss-server -s /root/ss-config.json -u" "ss"
    systemctl enable ss.service
fi

if [[ "${platform}" == "2" ]]; then
    service_template "/root/overture/overture-linux-amd64 -c /root/overture/config.json" "overture"
    systemctl enable overture.service
    service_template "/usr/local/shadowsocks/bin/ss-redir -c /root/ss-config.json -u" "ss"
    systemctl enable ss.service
    service_template "/root/iptables-config.sh" "iptables-config"
    systemctl enable iptables-config.service
fi

echo "------ Generating start script and give them root privilege"
if [[ "${platform}" == "1" ]]; then
    echo "#! /bin/sh
    ./root/tinyvpn/tinyvpn_amd64 -s -l0.0.0.0:14096 -f $fec --sub-net $subnet -k $password" >/root/tinyvpn.sh
    echo "#! /bin/sh
    ./root/udp2raw/udp2raw -s -l0.0.0.0:$port -r127.0.0.1:14096 --raw-mode faketcp -a -k $password" >/root/udp2raw.sh
elif [[ "${platform}" == "2" ]]; then
    echo "#! /bin/sh
    ./root/tinyvpn/tinyvpn_amd64 -c -r127.0.0.1:14096 -f $fec --sub-net $subnet --tun-dev $tunnel --keep-reconnect -k $password" >/root/tinyvpn.sh
    echo "#! /bin/sh
    ./root/udp2raw/udp2raw -c -r$ip:$port -l 127.0.0.1:14096 --raw-mode faketcp -a -k $password" >/root/udp2raw.sh
fi

chmod +x /root/tinyvpn.sh
chmod +x /root/udp2raw.sh

if [[ "${platform}" == "2" ]]; then
    iptables_configure ${ip}
    chmod +x /root/iptables-config.sh
fi

echo "------ Cleaning up"
systemctl start ss.service
systemctl start tinyvpn.service
systemctl start udp2raw.service

if [[ "${platform}" == "2" ]]; then
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
    systemctl start overture.service
    systemctl start iptables-config.service
    rm -rf /root/overture-linux-amd64.zip
fi

clear
if [[ "${platform}" == "1" ]]; then
    echo -e "Congratulations, ${green}Server${plain} install completed!"
    echo -e "${red}Copy the info below as you need them in your client script!${plain}"
    echo -e "Your Server IP                   : ${red} $(get_ip) ${plain}"
    echo -e "Your tinyfecVPN sub net          : ${red} ${subnet} ${plain}"
    echo -e "Your tinyfecVPN fec setting      : ${red} ${fec} ${plain}"
    echo -e "Your udp2raw Port                : ${red} ${port} ${plain}"
    echo -e "Your upd2raw/tinyfecVPN password : ${red} ${password} ${plain}"
    echo -e "Your shadowsocks Port            : ${red} ${ssport} ${plain}"
    echo -e "Your shadowsocks Password        : ${red} ${sspwd} ${plain}"
elif [[ "${platform}" == "2" ]]; then
    echo -e "Congratulations, ${green}Client${plain} install completed!"
fi
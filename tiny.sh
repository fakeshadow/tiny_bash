#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Server/Client script for tinyfecVPN + udp2raw + shadowsocksR + overture

# System Required: Ubuntu 20

# Important:
# This script is for learning bash operations. Please delete all the compiled files after you done with it.

# Credits:
# @Teddysun <i@teddysun.com> for copy paste scripts

# links
tiny_vpn_repo="https://github.com/wangyu-/tinyfecVPN.git"
udp2raw_repo="https://github.com/wangyu-/udp2raw-tunnel.git"
ssr_server_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"
ssr_client_url="https://github.com/shadowsocksr-backup/shadowsocksr-libev.git"
overture_url="https://github.com/shawn1m/overture/releases/download/v1.8/overture-linux-amd64.zip"

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

version_ge(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

version_gt(){
    test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"
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

download(){
    local filename=$(basename $1)
    if [[ -f ${1} ]]; then
        echo "${filename} [found]"
    else
        echo "${filename} not found, download now..."
        wget --no-check-certificate -c -t3 -T60 -O ${1} ${2}
        if [[ $? -ne 0 ]]; then
            echo -e "[${red}Error${plain}] Download ${filename} failed."
            exit 1
        fi
    fi
}

enable_ipv4_forward() {
cat <<'EOF' > /etc/sysctl.conf
net.ipv4.ip_forward=1
EOF
sysctl -p
}

create_service() {
cat <<EOF > /etc/systemd/system/${2}.service
[Unit]
Wants=network-online.target
After=network-online.target

[Service]
Type=idle
ExecStart=$1
Restart=always

[Install]
WantedBy=basic.target
EOF
systemctl enable ${2}.service
}

create_chnroutes() {
mkdir /etc/chnroutes
cat <<'EOF' > /etc/cron.weekly/chnroutes
#!/usr/bin/env bash

FILEPATH=/root/temp2333
FILENAME=chnroutes
TARGETPATH=/etc/chnroutes/

rm -rf $FILEPATH
mkdir $FILEPATH
cd $FILEPATH
curl -sL https://raw.githubusercontent.com/zealic/autorosvpn/master/chnroutes.txt | egrep -v '^$|^#' > $FILENAME

FILESIZE=$(stat -c%s "$FILENAME")

if [[ $FILESIZE > 10000 ]]; then
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

    ipset -N chnroutes hash:net
    for i in `cat $FILENAME`; do echo ipset -A chnroutes $i >> ipset.sh; done
    chmod +x ipset.sh && ./ipset.sh
    ipset save chnroutes > chnroutes.ipset

    rm -rf "${TARGETPATH}"chnroutes.ipset
    mv chnroutes.ipset "${TARGETPATH}"chnroutes.ipset
    rm -rf $FILEPATH
    cd / && ./etc/iptables/iptables.sh
fi
EOF
chmod +x /etc/cron.weekly/chnroutes
}

iptables_configure() {
mkdir /etc/iptables
cat <<EOF > /etc/iptables/iptables.sh
#!/usr/bin/env bash

ip rule add fwmark 0x01/0x01 table 100
ip route add local 0.0.0.0/0 dev lo table 100

ipset destroy chnroutes
ipset restore < /etc/chnroutes/chnroutes.ipset

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
iptables -t mangle -A ssudp -d 114.114.114.114/32 -j RETURN

iptables -t mangle -A ssudp -m set --match-set chnroutes dst -j RETURN
iptables -t mangle -A ssudp -p udp -j TPROXY --on-port 1081 --tproxy-mark 0x01/0x0
iptables -t mangle -A PREROUTING -p udp -j ssudp
EOF
chmod +x /etc/iptables/iptables.sh
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
apt install git ipset unzip build-essential cmake libsodium-dev libpcre3 libpcre3-dev libssl-dev zlib1g-dev -y
if [[ "${platform}" == "1" ]]; then
    apt install python -y
fi

if [[ "${platform}" == "2" ]]; then
    echo "------ Downloading release files"
    cd /root/
    download "overture-linux-amd64.zip" ${overture_url}
    unzip overture-linux-amd64.zip -d /usr/local/overture
fi

echo "------ Downloading repos"
git clone --recursive ${tiny_vpn_repo} /root/tinyvpn
git clone ${udp2raw_repo} /root/udp2raw

if [[ "${platform}" == "1" ]]; then
    download "3.2.2.tar.gz" ${ssr_server_url}
elif [[ "${platform}" == "2" ]]; then
    git clone ${ssr_client_url} /root/shadowsocksr
fi

echo "------ Compiling repos"

cd /root/tinyvpn
./makefile
mkdir /usr/local/tinyvpn
mv tinyvpn_amd64 /usr/local/tinyvpn/tinyvpn_amd64

cd /root/udp2raw
make
mkdir /usr/local/udp2raw
mv udp2raw /usr/local/udp2raw/udp2raw

if [[ "${platform}" == "1" ]]; then
    cd /root/
    tar zxf 3.2.2.tar.gz
    mv /root/shadowsocksr-3.2.2 /usr/local/shadowsocksr
elif [[ "${platform}" == "2" ]]; then
    cd /root/shadowsocksr
    export CFLAGS="${CFLAGS} -Wall -O3 -pipe -Wno-format-truncation -Wno-error=format-overflow -Wno-error=pointer-arith -Wno-error=stringop-truncation -Wno-error=sizeof-pointer-memaccess"
    ./configure --prefix=/usr/local/shadowsocksr --disable-documentation
    make && make install
fi

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

echo "Enter your shadowsocksr server port"
read -p "Default(16541): " ssport
[[ -z "${ssport}" ]] && ssport="16541"

echo "Enter your shadowsocksr password"
read -p "Default(fakeshadow): " sspwd
[[ -z "${sspwd}" ]] && sspwd="fakeshadow"

echo "------ Generating ss config file"
if check_kernel_version && check_kernel_headers; then
        fast_open="true"
    else
        fast_open="false"
fi

mkdir /etc/shadowsocksr
if [[ "${platform}" == "1" ]]; then
cat >/etc/shadowsocksr/config.json <<-EOF
{
    "server":"0.0.0.0",
    "server_ipv6":"::",
    "server_port":${ssport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${sspwd}",
    "method":"none",
    "protocol":"origin",
    "protocol_param":"",
    "obfs":"plain",
    "obfs_param":"",
    "timeout":120,
    "udp_timeout": 60,
    "redirect":"",
    "dns_ipv6":false,
    "fast_open":${fast_open},
    "workers":1
}
EOF
elif [[ "${platform}" == "2" ]]; then
cat >/etc/shadowsocksr/config.json <<-EOF
{
    "server": "${subnet%.0}.1",
    "server_port": ${ssport},
    "local_address": "0.0.0.0",
    "local_port": 1081,
    "password": "${sspwd}",
    "method":"none",
    "protocol":"origin",
    "protocol_param":"",
    "obfs":"plain",
    "obfs_param":"",
    "timeout": 120,
    "udp_timeout": 60,
    "fast_open": ${fast_open}
}
EOF
fi

echo "------ Enabling services"
create_service "/etc/tinyvpn/tinyvpn.sh" "tinyvpn"
create_service "/etc/udp2raw/udp2raw.sh" "udp2raw"

if [[ "${platform}" == "1" ]]; then
    create_service "python /usr/local/shadowsocksr/shadowsocks/server.py -c /etc/shadowsocksr/config.json" "shadowsocksr"
fi

if [[ "${platform}" == "2" ]]; then
    create_service "/usr/local/overture/overture-linux-amd64 -c /usr/local/overture/config.yml" "overture"
    # start overture service early so we have correct dns when curl for chnroutes
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
    systemctl start overture.service

    create_service "/usr/local/shadowsocksr/bin/ss-redir -c /etc/shadowsocksr/config.json -u" "shadowsocksr"
fi

echo "------ Generating start script and give them root privilege"
mkdir /etc/tinyvpn
mkdir /etc/udp2raw

if [[ "${platform}" == "1" ]]; then
    echo "#!/usr/bin/env bash
    ./usr/local/tinyvpn/tinyvpn_amd64 -s -l0.0.0.0:14096 -f $fec --sub-net $subnet -k $password" >/etc/tinyvpn/tinyvpn.sh
    echo "#!/usr/bin/env bash
    ./usr/local/udp2raw/udp2raw -s -l0.0.0.0:$port -r127.0.0.1:14096 --raw-mode faketcp -a -k $password" >/etc/udp2raw/udp2raw.sh
elif [[ "${platform}" == "2" ]]; then
    echo "#!/usr/bin/env bash
    ./usr/local/tinyvpn/tinyvpn_amd64 -c -r127.0.0.1:14096 -f $fec --sub-net $subnet --tun-dev $tunnel --keep-reconnect -k $password" >/etc/tinyvpn/tinyvpn.sh
    echo "#!/usr/bin/env bash
    ./usr/local/udp2raw/udp2raw -c -r$ip:$port -l 127.0.0.1:14096 --raw-mode faketcp -a -k $password" >/etc/udp2raw/udp2raw.sh
fi

chmod +x /etc/tinyvpn/tinyvpn.sh
chmod +x /etc/udp2raw/udp2raw.sh

if [[ "${platform}" == "2" ]]; then

echo "------ Configuring iptables and ipset"
create_chnroutes
iptables_configure ${ip}
/etc/cron.weekly/chnroutes

cat <<EOF > /etc/systemd/system/iptables.service
#!/usr/bin/env bash
[Unit]
Wants=network-online.target
After=network-online.target

[Service]
Type=idle
ExecStart=/etc/iptables/iptables.sh

[Install]
WantedBy=basic.target
EOF
systemctl enable iptables.service
systemctl start iptables.service
fi

echo "------ Cleaning up"
if [[ "${platform}" == "2" ]]; then
    enable_ipv4_forward
fi
systemctl start shadowsocksr.service
systemctl start tinyvpn.service
systemctl start udp2raw.service

rm -rf /root/tinyvpn
rm -rf /root/udp2raw
rm -rf /root/overture
rm -rf /root/shadowsocksr
rm -rf /root/shadowsocksr-3.2.2
rm -rf /root/3.2.2.tar.gz
rm -rf /root/overture-linux-amd64.zip
rm -rf /root/overture

clear
if [[ "${platform}" == "1" ]]; then
    echo -e "Congratulations, ${green}Server${plain} install completed!"
    echo -e "${red}Copy the info below as you need them in your client script!${plain}"
    echo -e "Your Server IP                   : ${red} $(get_ip) ${plain}"
    echo -e "Your tinyfecVPN sub net          : ${red} ${subnet} ${plain}"
    echo -e "Your tinyfecVPN fec setting      : ${red} ${fec} ${plain}"
    echo -e "Your udp2raw Port                : ${red} ${port} ${plain}"
    echo -e "Your upd2raw/tinyfecVPN password : ${red} ${password} ${plain}"
    echo -e "Your shadowsocksr Port           : ${red} ${ssport} ${plain}"
    echo -e "Your shadowsocksr Password       : ${red} ${sspwd} ${plain}"
elif [[ "${platform}" == "2" ]]; then
    echo -e "Congratulations, ${green}Client${plain} install completed!"
fi
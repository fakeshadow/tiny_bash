### VLESS+Reality 透明网关一键脚本

服务端 / 客户端使用不同的 core，但通过 VLESS+Reality 协议互通：

- **服务端**：`sing-box`，监听 VLESS+Reality on **TCP/443**（手机、桌面、客户端网关都连这一个入口）。
- **客户端**：`xray-core` + `dokodemo-door` TPROXY 入站 + VLESS+Reality+Vision 出站，作为局域网透明网关。
  - LAN 设备指网关为默认网关即可，无需在每台设备上装客户端。
  - 国内流量按 IP 直连不走代理（每周自动刷新 `chnroutes2` 路由表）。
  - 国外流量走代理隧道。

为什么服务端是 sing-box、客户端是 xray？因为：
- 透明网关这个场景，xray 的 TPROXY + dokodemo-door 是 Project X 官方文档里被验证多年的架构，OpenClash / luci-app-xray 等成熟项目都用这套。
- 服务端跑 sing-box 没有任何问题，VLESS+Reality 协议互通。

#### 适用系统

`Ubuntu 26.04`

#### 仓库地址

- 主仓库（GitHub）：<https://github.com/fakeshadow/tiny_bash>
- 国内镜像（Gitee）：<https://gitee.com/fakeshadow/tiny_bash> — 与主仓库内容一致，国内访问更稳定。

#### 使用方法

1. 用 root 账户登录（或本地有 sudo 权限）。
2. 下载脚本——**国内（含国内主机搭建客户端）建议用 Gitee 镜像**：

   ```sh
   # 国内（推荐）
   wget --no-check-certificate https://gitee.com/fakeshadow/tiny_bash/raw/master/tiny.sh
   ```

   ```sh
   # 海外服务端 / GitHub 直连可用时
   wget --no-check-certificate https://raw.githubusercontent.com/fakeshadow/tiny_bash/master/tiny.sh
   ```

3. `chmod +x tiny.sh`
4. `sudo ./tiny.sh`

提示选 1（Server）或 2（Client）。

#### 服务端流程

只问一个问题：

- **Reality serverName**：要伪装的真实 TLS 网站，默认 `www.cloudflare.com`。

跑完后终端会打印一组凭据，**保存好**——客户端脚本和手机客户端都需要这些值：

| 字段 | 用途 |
|---|---|
| `Address` | 服务端公网 IP |
| `Port` | `443` |
| `UUID` | VLESS 用户标识 |
| `Flow` | `xtls-rprx-vision` |
| `Public key` | Reality 公钥 |
| `Short ID` | Reality short-id |
| `ServerName` | 上面填的伪装站点 |
| `Fingerprint` | `chrome` |

#### 客户端流程

会依次问 5 个值，全部从服务端的输出里复制：

1. Server IP
2. Reality UUID
3. Reality public key
4. Reality short ID
5. Reality serverName（默认 `www.cloudflare.com`，需与服务端一致）
6. Reality spiderX（可选，回车留空即可）

跑完之后会启动 `xray` / `nftables` / `tproxy-route` 三个服务，并自动拉取一次 `chnroutes2` 国内 IP 表。

把 LAN 内其他设备的默认网关指到这台机器的 LAN IP，就完事了——这些设备不需要装任何代理客户端。

#### xray 二进制下载（国内镜像链）

国内访问 GitHub 极不稳定，所以脚本内置了多镜像 **依次尝试** 的下载链 [`xray_url_templates`](tiny.sh)：

1. `gh-proxy.com`
2. `ghfast.top`
3. `kkgithub.com`
4. `gh.ddlc.top`
5. GitHub 直连（兜底）

每个 URL 都是脚本编写时实际探测过的（HTTP 200 + 真实 ZIP 头字节），但镜像存活率每月都在变——如果某个镜像挂了，编辑 `tiny.sh` 顶部的 `xray_url_templates` 数组替换即可。

##### 全部镜像都挂了的应急办法

从手上任何能访问 GitHub 的机器（比如服务端本身）下载，scp 到网关，然后预放好 `xray` 二进制：

```sh
# 在能访问 GitHub 的机器上：
wget https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip
scp Xray-linux-64.zip 网关:/tmp/

# 在网关上：
sudo unzip /tmp/Xray-linux-64.zip -d /tmp/xray
sudo install -m 755 /tmp/xray/xray /usr/local/bin/xray

# 重新跑 tiny.sh，它会检测到 xray 已存在，跳过下载
sudo ./tiny.sh
```

#### 国内分流（chnroutes2）

客户端会安装：

- `/usr/local/sbin/update-chnroutes`：从 [misakaio/chnroutes2](https://github.com/misakaio/chnroutes2) 拉取最新国内 IP 段，原子化加载到 `nft inet xray cn_ipv4` 集合。
- `/etc/cron.weekly/update-chnroutes`：每周自动刷新一次。
- `/etc/nftables.d/chnroutes.nft`：被 `/etc/nftables.conf` 包含，重启后自动恢复。

`nft prerouting` 链里有这条规则：

```
ip daddr @cn_ipv4 return
```

匹配到国内 IP 的包直接 `return`，不走 TPROXY，由内核正常 forward 出 WAN——零用户态开销，全 LAN 速。

手动刷新：

```sh
sudo /usr/local/sbin/update-chnroutes
```

#### 健康检查

```sh
# 服务都跑起来了吗？
sudo systemctl status xray nftables tproxy-route

# 看 xray 实时日志
sudo journalctl -u xray -f

# 国内 IP 集是否加载（应有几千条）
sudo nft list set inet xray cn_ipv4 | wc -l

# fwmark 策略路由是否生效
ip rule | grep fwmark      # 应有 'fwmark 0x1 lookup 100'
ip route show table 100    # 应为 'local default dev lo scope host'

# 在 LAN 内任意一台设备上（已把网关指向本机）
curl https://ifconfig.me   # 应返回服务端的 IP，不是网关 WAN IP
```

#### 一些已知坑（已经踩过，配置里都改好了）

- **`sniffing.routeOnly: false`**（不是默认的 true）。如果改成 true，YouTube 这类严格按地理位置分发的 CDN 会在 TLS 握手中途 RST 连接（`PR_END_OF_FILE_ERROR`），原因是 LAN 端 DNS 解析到的国内 IP 跟服务端的源地区对不上。设成 false 让服务端按 SNI 域名重新解析就好了。
- **TPROXY 的循环避免**：xray 的 `proxy` / `direct` 出站都打了 `mark: 255`（fwmark `0x000000ff`），nftables 的 `prerouting` 链 `meta mark 0x000000ff return` 让 xray 自己发出去的流量跳过 TPROXY，否则会无限循环。
- **服务端只跑 VLESS+Reality**，没有 hysteria2。Hysteria2 在 2026 年 GFW 的 SNI-QUIC 检测下识别率约 32%（即 68% 通过率），且持续 UDP/443 流量会让 IP 被打标，得不偿失。

#### 卸载 / 维护

```sh
# 临时停
sudo systemctl stop xray nftables tproxy-route

# 不再开机自启
sudo systemctl disable xray nftables tproxy-route

# 看日志
sudo journalctl -u xray -n 200

# 配置文件位置
/usr/local/etc/xray/config.json    # xray 配置
/etc/nftables.conf                 # TPROXY 规则
/etc/nftables.d/chnroutes.nft      # 国内 IP 集（由 cron 维护，别手改）
```

#### 关于服务端

服务端这边没有透明网关，配置很简单——仅监听 VLESS+Reality on TCP/443，所有进来的流量直出。配置文件 `/etc/sing-box/config.json`，可以手动编辑：

```sh
# 改完后
sudo /usr/local/bin/sing-box -C /etc/sing-box check    # 校验配置
sudo systemctl restart sing-box
```

#### Important

This script is for learning bash operations. 用完请自行清理残留文件。

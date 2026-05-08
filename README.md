### sing-box 一键脚本（VLESS+Reality + Hysteria2）

服务端 / 客户端都跑同一份 `sing-box`：

- **服务端**：同时监听
  - VLESS+Reality on **TCP/443**（手机 / 桌面客户端，例如 v2rayNG）
  - Hysteria2 on **UDP/443**（家里那台网关用的客户端）
- **客户端**：`tun` 入站 + Hysteria2 出站，自动更新 `geoip-cn` / `geosite-cn` 规则集，国内流量直连。

#### 适用系统:
`Ubuntu 26.04`

#### 使用方法:

- 用 root 登录系统（或本地有 sudo）
- 下载脚本：

  ```sh
  wget --no-check-certificate https://raw.githubusercontent.com/fakeshadow/tiny_bash/master/tiny.sh
  ```

  在国内访问 GitHub 不稳定时，可以前置一个镜像：

  ```sh
  wget --no-check-certificate https://ghfast.top/https://raw.githubusercontent.com/fakeshadow/tiny_bash/master/tiny.sh
  ```

- `chmod +x tiny.sh`
- `./tiny.sh`

按提示选 1（Server）或 2（Client）即可。

#### sing-box 二进制下载来源

脚本内 `singbox_url_gh` / `singbox_url_mirror` 控制 sing-box 二进制的下载地址：

- **服务端**：直接走 GitHub Releases（境外机器一般够快）。
- **客户端**：先尝试 `ghfast.top` 镜像，失败再回退到 GitHub Releases。

如果 `ghfast.top` 抽风了，把 `singbox_url_mirror` 改成下面任一个即可：

- `https://mirror.ghproxy.com/https://github.com/...`
- `https://gh-proxy.com/https://github.com/...`
- `https://github.moeyy.xyz/https://github.com/...`
- `https://github.akams.cn/https://github.com/...`

#### 服务端打印的参数怎么用

跑完服务端后，终端会打印两组凭据：

- Reality（TCP/443）：`UUID`、`Public key`、`Short ID`、`ServerName`、`Flow=xtls-rprx-vision`、`Fingerprint=chrome`
  → 复制到 v2rayNG / Clash Meta / sing-box 客户端的 VLESS+Reality 配置里。
- Hysteria2（UDP/443）：`Password`、`Salamander obfs`、TLS 选 insecure（自签证书）
  → 客户端脚本会问你这两个密码。

#### 卸载 / 维护

- `systemctl stop sing-box` — 临时停服务
- `systemctl disable sing-box` — 不再开机自启
- `journalctl -u sing-box -n 200` — 看日志
- 配置文件在 `/etc/sing-box/config.json`，规则集缓存在 `/var/lib/sing-box/cache.db`

#### Important

This script is for learning bash operations. 用完请自行清理残留文件。

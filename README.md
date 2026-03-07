# nftables 代理节点防火墙管理脚本

> **port.sh v5.5** — 专为代理节点设计的全自动 nftables 防火墙，一键配置，开机永久生效。

---

## 功能特性

- **全自动识别**：自动扫描 X-UI / 3x-ui / Marzban / sing-box / xray / Hysteria2 / WireGuard / Trojan / TUIC 等所有主流面板和代理软件的监听端口，无需手动填写
- **Hysteria2 端口跳跃**：自动读取配置文件中的 `portHopping` 范围，生成 nftables `redirect` 规则，IPv4 + IPv6 一条规则同时覆盖
- **SSH 防暴力破解**：per-IP 令牌桶限速，60 秒内同一来源超过 10 次新连接自动封锁
- **IPv6 双栈**：单一 `inet` 表统一管理 IPv4 + IPv6，无需两套规则
- **Docker 友好**：自动检测所有 bridge 网络接口（`docker0` / `br-xxxx`），不修改 `daemon.json`，-p 端口映射正常工作
- **原子加载**：规则更新通过 nftables 内核 batch 事务完成，无规则空窗期，加载失败时旧规则自动保留
- **开机持久化**：规则自动写入 `/etc/nftables.conf`，由 `nftables.service` 开机加载

---

## 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Ubuntu 22.04 / 24.04（推荐） |
| Linux 内核 | ≥ 5.2（支持 inet NAT） |
| 权限 | root |
| 依赖 | nftables、iproute2、python3（自动安装） |

> ⚠️ **不支持** CentOS 7、Debian 10 等内核低于 5.2 的系统

---

## 快速开始

### 一键运行（推荐）

```bash
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/nftables/refs/heads/main/nftables.sh)
```

脚本会自动完成：依赖安装 → 端口扫描 → 规则生成 → 原子加载 → 持久化保存。

---

## 命令参数

```bash
bash nftables.sh [选项]
```

| 参数 | 说明 |
|------|------|
| （无参数） | 全自动检测并配置防火墙（**常用**） |
| `--dry-run` | 预览模式，仅显示将生成的规则，不做任何修改 |
| `--status` | 显示当前防火墙状态、开放端口、规则集 |
| `--add-hop` | 手动交互式添加 Hysteria2 端口跳跃规则 |
| `--reset` | 清除本脚本生成的所有规则（全部放行），需确认 |
| `--help` | 显示帮助信息 |

---

## 使用场景

### 场景一：首次配置 / 更新端口后重新配置

```bash
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/nftables/refs/heads/main/nftables.sh)
```

> 每次在面板里新增节点后，重新执行一次此命令即可同步防火墙规则。

---

### 场景二：先预览再执行

```bash
# 第一步：预览将生成的规则（不修改任何配置）
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/nftables/refs/heads/main/nftables.sh) --dry-run

# 确认无误后，第二步：正式执行
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/nftables/refs/heads/main/nftables.sh)
```

---

### 场景三：手动添加 Hysteria2 端口跳跃

Hysteria2 配置文件中设置了 `portHopping` 时脚本会自动检测。如果自动检测失败，可手动添加：

```bash
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/nftables/refs/heads/main/nftables.sh) --add-hop
```

按提示输入：
```
跳跃端口范围（如 20000-50000）: 20000-50000
目标端口（代理实际监听端口，如 443）: 443
```

---

### 场景四：查看当前状态

```bash
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/nftables/refs/heads/main/nftables.sh) --status
```

输出内容包括：nftables 服务状态、当前开放端口、端口跳跃规则、实时监听进程、完整规则集。

---

### 场景五：紧急解除防火墙

SSH 被锁或需要调试时：

```bash
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/nftables/refs/heads/main/nftables.sh) --reset
```

> 只删除本脚本管理的两张表（`inet filter` / `inet nat`），不影响 fail2ban 等其他工具的规则。

---

## 常用 nftables 命令

```bash
# 查看完整规则集
nft list ruleset

# 查看过滤规则（INPUT / FORWARD）
nft list table inet filter

# 查看 NAT 规则（端口跳跃）
nft list table inet nat

# 查看统计计数（命中次数/流量）
nft list ruleset -a

# 查看 SSH 限速封锁列表（当前被限速的 IP）
nft list set inet filter ssh_limit_v4
nft list set inet filter ssh_limit_v6
```

---

## 注意事项

### ⚠️ 必读：云平台安全组

本脚本只管理**服务器本机防火墙**，云平台安全组是独立的第一层过滤，两者都要配置：

| 云平台 | 安全组位置 |
|--------|-----------|
| 甲骨文 Oracle | VCN → 安全列表 / NSG → 入站规则 |
| AWS | EC2 → 安全组 → Inbound Rules |
| 阿里云 / 腾讯云 | 实例 → 安全组规则 |
| Vultr / Hetzner | 通常无安全组，本机防火墙即唯一一层 |

---

### ⚠️ X-UI / 3x-ui / Marzban 用户

脚本通过以下方式检测端口：
- **X-UI / 3x-ui**：直接读取 SQLite 数据库（`x-ui.db`），只读取**已启用**的节点
- **Marzban**：读取 `.env` 文件中的 `UVICORN_PORT`，节点端口依赖进程监听

**执行脚本前，请确保所有节点处于运行中状态**，否则未监听的端口不会被放行。

---

### ⚠️ 与其他防火墙工具的冲突

脚本会自动停止并禁用以下服务（防止规则冲突）：

- `firewalld`
- `ufw`
- `iptables` / `ip6tables`（服务，非命令本身）

如果你的系统依赖 `firewalld` 或 `ufw`，请勿使用本脚本。

---

### ⚠️ 面板管理端口安全

X-UI (54321) 等面板管理端口**不建议直接对公网开放**，建议通过 SSH 隧道访问：

```bash
# 本地执行，将远程 54321 映射到本地
ssh -L 54321:127.0.0.1:54321 root@服务器IP

# 然后在本地浏览器访问（安全）
http://127.0.0.1:54321
```

---

### ⚠️ Docker 用户

- 脚本**不会修改** `/etc/docker/daemon.json`，Docker 的 `-p` 端口映射正常工作
- 脚本自动检测所有 Docker bridge 网络（包括 `docker network create` 创建的自定义网络）
- 新增 Docker 网络后，重新执行脚本一次以更新 masquerade 规则

---

## 防火墙策略说明

| 链 | 默认策略 | 说明 |
|----|---------|------|
| `input` | DROP | 白名单模式，只放行明确声明的端口 |
| `forward` | ACCEPT | 允许转发（Docker DNAT 路径必须） |
| `output` | ACCEPT | 出站不限制 |

**INPUT 链放行规则（按顺序）：**

1. 回环接口 `lo` → 全放行
2. `ct state invalid` → DROP（过滤伪造包）
3. `ct state established/related` → ACCEPT（已建立连接）
4. ICMPv4 echo-request → 限速放行（5/秒，防洪泛）
5. ICMPv6 NDP 必要类型 → 全放行（IPv6 地址解析/路由发现必须）
6. SSH 端口 → 限速放行（per-IP 10次/60秒，超限封锁）
7. 代理端口 → TCP/UDP 全放行
8. 端口跳跃范围 → TCP/UDP 全放行
9. 其余 → 限速记录日志后 DROP

---

## 文件位置

| 文件 | 说明 |
|------|------|
| `/etc/nftables.conf` | 持久化规则文件，开机自动加载 |
| `/etc/sysctl.d/98-port-firewall.conf` | 内核参数（ip_forward、rp_filter 等） |

# nftables 防火墙脚本

## nftables 版本 port.sh

基于 iptables 版本的完全重写，使用 nftables 作为防火墙后端。

### 相比 iptables 版本的改进

- 使用 `table inet filter` 统一管理 IPv4 + IPv6
- 使用 `redirect to :PORT` 实现端口跳跃（比 DNAT 更简洁）
- 原子规则加载（无防御真空期）
- 现代 SSH 防暴力破解（named dynamic set）
- 自动检测 Docker 网络并生成 masquerade 规则

### 特性

- IPv4 + IPv6 双栈统一管理
- Oracle Cloud ARM / Ubuntu 22.04/24.04 兼容
- Docker 环境完全支持
- 内核 ≥ 5.2 要求（Ubuntu 22.04 = 5.15 ✓）

### 使用方法

```bash
# 一键安装
bash <(curl -fsSL https://raw.githubusercontent.com/vpn3288/nftables/main/nftables.sh)

# 查看状态
bash nftables.sh --status

# 重置防火墙
bash nftables.sh --reset

# 添加端口跳跃
bash nftables.sh --add-hop
```

### 系统要求

- Ubuntu 22.04 / 24.04
- Debian 11 / 12
- 内核 ≥ 5.2
- root 权限

### 支持的协议

| 协议 | 端口检测 | 备注 |
|------|----------|------|
| Hysteria2 | 自动 | 使用 redirect 实现端口跳跃 |
| X-UI | 数据库 | 需要 sqlite3 |
| sing-box | 配置文件 | JSON/YAML |
| WireGuard | 系统 | 自动检测 |
| Docker | 自动检测 | 生成 masquerade 规则 |

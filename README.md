# 🛡️ nftables 防火墙管理脚本

适用于**自建代理节点**、不使用一键脚本的服务器。  
运行时自动禁用 iptables / ufw / firewalld，独占防火墙控制权。

---

## 🚀 一键运行

```bash
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/nftables/refs/heads/main/duankou.sh)
```

---

## ✨ 功能特性

- 🔍 **自动检测端口** — 扫描代理进程实际监听的端口，无需手动填写
- 🦘 **端口跳跃（Port Hopping）** — 自动检测 Hysteria2 跳跃配置，支持手动添加
- 🔒 **SSH 防暴力破解** — 限制每分钟最多 4 次新连接
- 🚫 **自动禁用 iptables / ufw** — 独占防火墙，避免规则冲突
- 💾 **重启持久化** — 规则重启后自动恢复
- 📋 **预览模式** — `--dry-run` 查看规则，不实际修改



## 🔧 常用命令

**查看当前状态：**
```bash
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/nftables/refs/heads/main/duankou.sh) --status
```

**手动添加端口跳跃：**
```bash
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/nftables/refs/heads/main/duankou.sh) --add-hop
```
```
端口范围（如 20000-50000）: 16820-16999
目标端口（代理实际监听端口）: 16801
✓ 端口跳跃 16820-16999 → 16801 添加完成
```

**预览模式（不实际修改）：**
```bash
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/nftables/refs/heads/main/duankou.sh) --dry-run
```

**重置防火墙（全部放行）：**
```bash
bash <(curl -sSL https://raw.githubusercontent.com/vpn3288/nftables/refs/heads/main/duankou.sh) --reset
```

---

## 🔧 参数说明

| 参数 | 说明 |
|------|------|
| `（无参数）` | 交互式完整配置（首次使用） |
| `--status` | 查看当前防火墙规则和端口状态 |
| `--add-hop` | 手动添加端口跳跃规则 |
| `--reset` | 清空所有规则，恢复全部放行 |
| `--dry-run` | 预览模式，显示规则但不实际应用 |
| `--help` | 显示帮助信息 |

---

## 🦘 端口跳跃说明

端口跳跃是 **Hysteria2** 的特有功能，客户端随机使用范围内的端口连接，有效对抗 QoS 限速。

```
客户端 → 随机端口（如 16820~16999 中任意一个）
                    ↓ NAT 转发
              代理服务监听端口（如 16801）
```

脚本会自动读取 Hysteria2 配置文件中的 `portHopping` / `portRange` 字段并应用，  
也可通过 `--add-hop` 手动添加。

---

## ❓ 常见问题

**Q：我用了 vasma / 3x-ui，能用这个脚本吗？**

不建议。vasma、3x-ui、233boy 等脚本内部会自动操作 iptables，与 nftables 同时使用会导致规则冲突，端口莫名不通。  
请改用 [iptables 版本](https://github.com/vpn3288/iptables)。

**Q：会不会把 SSH 端口关掉？**

不会。脚本自动检测当前 SSH 端口并放行，同时启用防暴力破解保护。

**Q：重启后规则还在吗？**

在。规则保存至 `/etc/nftables.conf`，nftables 服务配置为开机自启，重启后自动恢复。

**Q：如何查看当前生效的规则？**

```bash
nft list ruleset
```

---

## 🖥️ 系统支持

| 系统 | 版本 |
|------|------|
| Ubuntu | 22.04 / 24.04 |
| Debian | 11 / 12 |
| CentOS / RHEL | 8+ |
| Rocky / AlmaLinux | 8+ |

架构：`x86_64` / `aarch64`（甲骨文 ARM 云）

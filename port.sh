#!/bin/bash
# port.sh v5.0 — 代理节点防火墙管理脚本（nftables 版）
# 支持: Hysteria2端口跳跃 | X-UI/3x-ui/Marzban | sing-box | xray | v2ray | WireGuard | Trojan | TUIC | Naive
# 兼容: Ubuntu 22.04/24.04 | Oracle Cloud ARM | 各大 VPS | Docker 环境 | IPv6 双栈
#
# ══════════════════ v5.0 重大变更（iptables → nftables）══════════════════
# 【架构】
#   完全迁移至 nftables，禁用并屏蔽所有 iptables/ip6tables 服务
#   清空残留 iptables 规则，防止与 nftables 冲突
#
# 【table inet filter】
#   单表统一处理 IPv4 + IPv6，无需 iptables + ip6tables 两套命令
#   policy drop — 白名单模式，默认拒绝所有入站
#
# 【table inet nat】
#   端口跳跃改用 redirect to :PORT（nftables 原生重定向到本机）
#   比 iptables DNAT 更简洁：同一条规则同时覆盖 IPv4 和 IPv6
#   需要内核 ≥ 5.2（Ubuntu 22.04 = 5.15 ✓，Ubuntu 24.04 = 6.8+ ✓）
#
# 【SSH 防暴力破解】
#   改用 nftables meter（per-IP 令牌桶），比 iptables recent 模块
#   更精准、更高效，无需加载额外内核模块
#
# 【Docker 集成】
#   设置 daemon.json iptables=false，由 nftables 接管 masquerade
#   动态读取所有 Docker 网络子网，生成对应 masquerade 规则
#
# 【原子加载】
#   规则写入临时文件后 nft -f 一次性加载，无规则空窗期
#   save_rules 将当前 ruleset dump 到 /etc/nftables.conf 持久化
#
# ══════════════════════════════════════════════════════════════════════════
# 继承自 v4.3 的所有检测逻辑（未改动）：
#   • detect_ports: ss扫描 + Python解析器(JSONC注释) + SQLite + WireGuard + Marzban
#   • detect_hysteria_hop: YAML/JSON 配置文件解析（含JSONC注释剥离）
#   • is_blacklisted / add_port / port_in_hop_range（完全不变）
#   • 全部 A1-A14 / B1-B4 修复继续有效
# ══════════════════════════════════════════════════════════════════════════

set -uo pipefail

# ── 颜色 & 工具函数 ──────────────────────────────────────────
R="\033[31m" Y="\033[33m" G="\033[32m" C="\033[36m" B="\033[34m" W="\033[0m"
ok()   { echo -e "${G}✓ $*${W}"; }
warn() { echo -e "${Y}⚠  $*${W}"; }
err()  { echo -e "${R}✗ $*${W}"; exit 1; }
info() { echo -e "${C}→ $*${W}"; }
hr()   { echo -e "${B}──────────────────────────────────────────${W}"; }

[[ $(id -u) -eq 0 ]] || err "需要 root 权限"

SSH_PORT="" OPEN_PORTS=() HOP_RULES=() VERSION="5.0" DRY_RUN=false
_status=0 _reset=0 _addhop=0
_DOCKER_RUNNING=0    # 记录 Docker 是否在运行
_PY_PARSER=""        # Python 临时文件路径，EXIT trap 清理
_NFT_TMPFILE=""      # nftables 临时规则文件，EXIT trap 清理

for arg in "$@"; do case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --status)  _status=1 ;;
    --reset)   _reset=1 ;;
    --add-hop) _addhop=1 ;;
    --help|-h)
        echo "用法: bash port.sh [选项]"
        echo "  （无参数）    自动检测并配置防火墙"
        echo "  --dry-run     预览模式，不实际修改规则"
        echo "  --status      显示当前防火墙状态"
        echo "  --reset       清除所有规则（全部放行）"
        echo "  --add-hop     手动添加 Hysteria2 端口跳跃规则"
        echo "  --help        显示帮助"
        exit 0 ;;
    *) err "未知参数: $arg（用 --help 查看用法）" ;;
esac; done

EXCLUDE_PROCS="cloudflared|chronyd|dnsmasq|systemd-resolve|systemd\.resolve|named|unbound|ntpd|avahi|NetworkManager"

# ============================================================
# _cleanup: EXIT trap，清理所有临时文件
# ============================================================
_cleanup() {
    [[ -n "${_PY_PARSER:-}"   && -f "$_PY_PARSER"   ]] && rm -f "$_PY_PARSER"   2>/dev/null || true
    [[ -n "${_NFT_TMPFILE:-}" && -f "$_NFT_TMPFILE" ]] && rm -f "$_NFT_TMPFILE" 2>/dev/null || true
}
trap '_cleanup' EXIT
trap 'echo -e "\n${R}已中断${W}"; exit 130' INT TERM

# ============================================================
# get_public_ports: ss 扫描公网监听端口（全端口范围）
# ============================================================
get_public_ports() {
    ss -tulnp 2>/dev/null \
        | grep -vE '[[:space:]](127\.|::1)[^[:space:]]' \
        | grep -vE "($EXCLUDE_PROCS)" \
        | grep -oE '(\*|0\.0\.0\.0|\[?::\]?):[0-9]+' \
        | grep -oE '[0-9]+$' \
        | sort -un || true
}

# ============================================================
# install_deps: 安装 nftables，完全禁用 iptables，配置 sysctl
# ============================================================
install_deps() {
    local pkgs=()

    command -v nft     &>/dev/null || pkgs+=(nftables)
    command -v ss      &>/dev/null || pkgs+=(iproute2)
    command -v python3 &>/dev/null || pkgs+=(python3)

    # sqlite3：若存在 X-UI/3x-ui 数据库则自动安装
    local _need_sqlite=0
    for db in /etc/x-ui/x-ui.db /usr/local/x-ui/bin/x-ui.db \
              /opt/3x-ui/bin/x-ui.db /usr/local/x-ui/x-ui.db; do
        [[ -f "$db" ]] && _need_sqlite=1 && break
    done
    [[ $_need_sqlite -eq 1 ]] && ! command -v sqlite3 &>/dev/null && pkgs+=(sqlite3)

    if [[ ${#pkgs[@]} -gt 0 ]]; then
        info "安装依赖: ${pkgs[*]}"
        if command -v apt-get &>/dev/null; then
            apt-get update -qq 2>/dev/null || true
            apt-get install -y -qq "${pkgs[@]}" 2>/dev/null || true
        elif command -v dnf &>/dev/null; then
            dnf install -y -q "${pkgs[@]}" 2>/dev/null || true
        elif command -v yum &>/dev/null; then
            yum install -y -q "${pkgs[@]}" 2>/dev/null || true
        fi
    fi
    command -v nft &>/dev/null || err "nftables 安装失败，请手动安装后重试"

    # ── 完全禁用 iptables/ip6tables/iptables-restore ──────────
    # 使用 mask 防止被第三方脚本（面板安装脚本等）意外启动
    info "禁用并屏蔽 iptables 相关服务..."
    for svc in iptables ip6tables iptables-restore ip6tables-restore; do
        if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1 \
           | grep -q "^${svc}"; then
            systemctl stop    "${svc}" 2>/dev/null || true
            systemctl disable "${svc}" 2>/dev/null || true
            systemctl mask    "${svc}" 2>/dev/null || true
        fi
    done
    # 删除 port.sh v4.x 遗留的 iptables-restore.service 单元文件
    if [[ -f /etc/systemd/system/iptables-restore.service ]]; then
        rm -f /etc/systemd/system/iptables-restore.service
        systemctl daemon-reload 2>/dev/null || true
        ok "已删除旧版 iptables-restore.service"
    fi
    ok "iptables 服务已全部禁用/屏蔽"

    # ── 清空残留 iptables 规则（防止与 nftables 并行冲突）──────
    # 注意: Ubuntu 22.04+ 默认 iptables 指向 iptables-nft（基于 nftables），
    # 这里清空确保 nft 接管前无残留规则
    if command -v iptables &>/dev/null; then
        iptables -P INPUT   ACCEPT 2>/dev/null || true
        iptables -P FORWARD ACCEPT 2>/dev/null || true
        iptables -P OUTPUT  ACCEPT 2>/dev/null || true
        iptables -F         2>/dev/null || true
        iptables -X         2>/dev/null || true
        iptables -t nat    -F 2>/dev/null || true
        iptables -t nat    -X 2>/dev/null || true
        iptables -t mangle -F 2>/dev/null || true
    fi
    if command -v ip6tables &>/dev/null; then
        ip6tables -P INPUT   ACCEPT 2>/dev/null || true
        ip6tables -P FORWARD ACCEPT 2>/dev/null || true
        ip6tables -P OUTPUT  ACCEPT 2>/dev/null || true
        ip6tables -F         2>/dev/null || true
        ip6tables -X         2>/dev/null || true
        ip6tables -t nat    -F 2>/dev/null || true
        ip6tables -t nat    -X 2>/dev/null || true
        ip6tables -t mangle -F 2>/dev/null || true
    fi
    ok "残留 iptables 规则已清空"

    # ── 禁用 firewalld / ufw ───────────────────────────────────
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        warn "检测到 firewalld，停止并禁用..."
        systemctl disable --now firewalld 2>/dev/null || true
        ok "firewalld 已禁用"
    fi
    if systemctl is-active --quiet ufw 2>/dev/null; then
        warn "检测到 ufw，停止并禁用..."
        ufw --force disable 2>/dev/null || true
        systemctl disable --now ufw 2>/dev/null || true
        ok "ufw 已禁用"
    fi

    # ── sysctl 内核参数 ───────────────────────────────────────
    sysctl -w net.ipv4.ip_forward=1               &>/dev/null || true
    sysctl -w net.ipv6.conf.all.forwarding=1      &>/dev/null || true
    sysctl -w net.ipv6.conf.default.forwarding=1  &>/dev/null || true
    sysctl -w net.ipv4.conf.all.send_redirects=0      &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_redirects=0    &>/dev/null || true
    sysctl -w net.ipv4.conf.all.accept_source_route=0 &>/dev/null || true
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1  &>/dev/null || true
    sysctl -w net.ipv4.tcp_timestamps=0               &>/dev/null || true
    # rp_filter=2 宽松模式：=1 严格模式会丢弃 redirect/NAT 的 UDP 回程包
    sysctl -w net.ipv4.conf.all.rp_filter=2     &>/dev/null || true
    sysctl -w net.ipv4.conf.default.rp_filter=2 &>/dev/null || true

    cat > /etc/sysctl.d/98-port-firewall.conf << 'EOF'
# port.sh v5.0 (nftables) — 与 youhua.sh v2.4 / BBRplus 完全兼容
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.default.forwarding=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.tcp_timestamps=0
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
    sysctl -p /etc/sysctl.d/98-port-firewall.conf &>/dev/null || true
    ok "sysctl 参数已写入 /etc/sysctl.d/98-port-firewall.conf"
}

# ============================================================
# detect_ssh: 检测 SSH 端口
# ============================================================
detect_ssh() {
    SSH_PORT=$(ss -tlnp 2>/dev/null \
        | grep -E '\bsshd\b' \
        | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1)
    [[ -z "$SSH_PORT" ]] && \
        SSH_PORT=$(grep -E '^[[:space:]]*Port[[:space:]]' /etc/ssh/sshd_config 2>/dev/null \
            | awk '{print $2}' | head -1)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    ok "SSH 端口: $SSH_PORT"
}

# ============================================================
# parse_hop: 解析跳跃规则字符串 "20000-50000->443"
# ============================================================
parse_hop() {
    local rule=$1
    HOP_S="${rule%%-*}"
    local _rest="${rule#*-}"
    HOP_E="${_rest%%->*}"
    HOP_T="${rule##*>}"
}

# ============================================================
# port_in_hop_range: 检查端口是否落在跳跃范围内（空数组安全）
# ============================================================
port_in_hop_range() {
    local p=$1
    [[ ${#HOP_RULES[@]} -eq 0 ]] && return 1
    local rule
    for rule in "${HOP_RULES[@]}"; do
        parse_hop "$rule"
        [[ -n "${HOP_S:-}" && -n "${HOP_E:-}" ]] || continue
        [[ "$p" -ge "$HOP_S" && "$p" -le "$HOP_E" ]] && return 0
    done
    return 1
}

# ============================================================
# is_blacklisted: 危险/系统端口黑名单
# ============================================================
is_blacklisted() {
    local p=$1
    [[ "$p" == "$SSH_PORT" ]] && return 0
    case "$p" in
        23|25|53|69|111|135|137|138|139|445|514|631) return 0 ;;
        110|143|465|587|993|995) return 0 ;;
        1433|1521|3306|5432|6379|27017) return 0 ;;
        3389|5900|5901|5902|323|2049) return 0 ;;
        10080|10081|10082|10083|10084|10085|10086) return 0 ;;
    esac
    return 1
}

# ============================================================
# add_port: 将端口加入开放列表（带校验和去重，空数组安全）
# ============================================================
add_port() {
    local p=$1
    [[ "$p" =~ ^[0-9]+$ ]]              || return 0
    [[ "$p" -ge 1 && "$p" -le 65535 ]] || return 0
    is_blacklisted "$p"                  && return 0
    port_in_hop_range "$p"              && return 0
    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        [[ " ${OPEN_PORTS[*]} " =~ " $p " ]] && return 0
    fi
    OPEN_PORTS+=("$p")
}

# ============================================================
# detect_existing_hop_rules: 从当前 nftables NAT 读取已有跳跃规则
# 解析 "nft list table inet nat" 输出中的 redirect 规则
# 示例行: "udp dport 20000-50000 redirect to :443"
# ============================================================
detect_existing_hop_rules() {
    # 仅解析 udp 行（tcp 是同一规则对，不重复收集）
    while IFS= read -r line; do
        # 匹配: "[whitespace]udp dport S-E redirect to :T"
        if [[ "$line" =~ udp[[:space:]]+dport[[:space:]]+([0-9]+)-([0-9]+)[[:space:]].*redirect.*:([0-9]+) ]]; then
            local s="${BASH_REMATCH[1]}" e="${BASH_REMATCH[2]}" t="${BASH_REMATCH[3]}"
            local rule="${s}-${e}->${t}"
            if [[ ${#HOP_RULES[@]} -eq 0 ]] || \
               [[ ! " ${HOP_RULES[*]} " =~ " ${rule} " ]]; then
                HOP_RULES+=("$rule")
                info "读取已有跳跃规则: ${s}-${e} → ${t}"
            fi
        fi
    done < <(nft list table inet nat 2>/dev/null || true)
}

# ============================================================
# detect_hysteria_hop: 从 Hysteria2 配置文件检测端口跳跃
# ============================================================
detect_hysteria_hop() {
    local dirs=(
        /etc/hysteria  /etc/hysteria2
        /usr/local/etc/hysteria  /usr/local/etc/hysteria2
    )
    local file_names=(config server)

    for d in "${dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for fname in "${file_names[@]}"; do
            for ext in json yaml yml; do
                local f="${d}/${fname}.${ext}"
                [[ -f "$f" ]] || continue
                local listen_port="" hop_range=""

                if [[ "$ext" == "json" ]]; then
                    if command -v python3 &>/dev/null; then
                        listen_port=$(python3 - "$f" 2>/dev/null << 'PYEOF'
import json, sys, re

def strip_jsonc(s):
    """状态机剥离 // 和 /* */ 注释，正确跳过字符串内容（如 URL 中的 //）"""
    out=[]; i=0; n=len(s); in_str=False
    while i<n:
        c=s[i]
        if in_str:
            if c=='\\' and i+1<n: out.append(c); out.append(s[i+1]); i+=2; continue
            elif c=='"': in_str=False
            out.append(c)
        else:
            if c=='"': in_str=True; out.append(c)
            elif s[i:i+2]=='//':
                while i<n and s[i]!='\n': i+=1; continue
            elif s[i:i+2]=='/*':
                end=s.find('*/',i+2); i=(end+2) if end!=-1 else n; continue
            else: out.append(c)
        i+=1
    return ''.join(out)

try:
    with open(sys.argv[1], encoding='utf-8', errors='ignore') as fp:
        raw = fp.read()
    try:
        d = json.loads(raw)
    except json.JSONDecodeError:
        d = json.loads(strip_jsonc(raw))
    v = str(d.get('listen',''))
    if v:
        m = re.search(r':(\d+)$', v)
        if m: print(m.group(1)); raise SystemExit
    lp = d.get('listen_port')
    if isinstance(lp, int) and 1 <= lp <= 65535:
        print(lp)
except SystemExit: pass
except Exception: pass
PYEOF
                        )
                    fi
                    hop_range=$(grep -oE \
                        '"(portHopping|portRange|hop)"\s*:\s*"[0-9]+-[0-9]+"' \
                        "$f" 2>/dev/null \
                        | grep -oE '[0-9]+-[0-9]+' | head -1)
                else
                    listen_port=$(grep -E '^\s*listen\s*:' "$f" 2>/dev/null \
                        | awk -F: '{
                            for(i=NF;i>=1;i--) {
                                gsub(/[^0-9]/,"",$i)
                                if($i~/^[0-9]+$/ && $i+0>=1 && $i+0<=65535) {
                                    print $i; exit
                                }
                            }
                          }' | head -1)
                    hop_range=$(grep -E \
                        '^\s*(portHopping|portRange|hop)\s*:' \
                        "$f" 2>/dev/null \
                        | grep -oE '[0-9]+-[0-9]+' | head -1)
                fi

                if [[ -n "$listen_port" && -n "$hop_range" ]]; then
                    local rule="${hop_range}->${listen_port}"
                    local already=0
                    [[ ${#HOP_RULES[@]} -gt 0 ]] && \
                        [[ " ${HOP_RULES[*]} " =~ " ${rule} " ]] && already=1
                    if [[ $already -eq 0 ]]; then
                        HOP_RULES+=("$rule")
                        ok "检测到 Hysteria2 端口跳跃 ($f): $hop_range → $listen_port"
                    fi
                elif [[ -n "$listen_port" ]]; then
                    add_port "$listen_port"
                    info "Hysteria2 固定监听端口 ($f): $listen_port"
                fi
            done
        done
    done
}

# ============================================================
# detect_ports: 综合端口扫描（ss + 配置文件 + 数据库）
# ============================================================
detect_ports() {
    info "扫描公网监听端口..."

    # ── 1. ss 实时扫描 ────────────────────────────────────────
    while read -r port; do
        add_port "$port"
    done < <(get_public_ports)

    # ── 2. WireGuard 端口检测 ─────────────────────────────────
    if command -v wg &>/dev/null; then
        while IFS= read -r line; do
            local wg_port
            wg_port=$(echo "$line" | awk '{print $NF}')
            [[ "$wg_port" =~ ^[0-9]+$ ]] && add_port "$wg_port"
        done < <(wg show all listen-port 2>/dev/null || true)
    fi
    for wg_conf in /etc/wireguard/*.conf /usr/local/etc/wireguard/*.conf; do
        [[ -f "$wg_conf" ]] || continue
        local wg_port
        wg_port=$(grep -iE '^[[:space:]]*ListenPort[[:space:]]*=' "$wg_conf" \
            | grep -oE '[0-9]+' | head -1)
        [[ -n "$wg_port" ]] && add_port "$wg_port" && \
            info "WireGuard 配置端口 ($wg_conf): $wg_port"
    done

    # ── 3. Python 配置文件解析（JSONC 注释支持）──────────────
    _PY_PARSER=$(mktemp /tmp/_fw_parse_ports_XXXXXX.py)
    cat > "$_PY_PARSER" << 'PYEOF'
import json, sys, re, os

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

def parse_addr_port(v):
    if v is None: return None
    if isinstance(v, int): return v if 1 <= v <= 65535 else None
    s = str(v).strip()
    if s.isdigit():
        p = int(s); return p if 1 <= p <= 65535 else None
    m = re.search(r':(\d+)$', s)
    if m:
        p = int(m.group(1)); return p if 1 <= p <= 65535 else None
    return None

def is_local_bind(v):
    s = str(v or '').strip()
    return s.startswith('127.') or s in ('::1', 'localhost')

def extract_json(data):
    if not isinstance(data, dict): return []
    ports = []
    for inb in (data.get('inbounds') or []):
        if not isinstance(inb, dict): continue
        if is_local_bind(inb.get('listen', '')): continue
        for key in ('port', 'listen_port'):
            p = parse_addr_port(inb.get(key))
            if p: ports.append(p)
    for src in ([data.get('inbound')] + list(data.get('inboundDetour') or [])):
        if not isinstance(src, dict): continue
        if is_local_bind(src.get('listen', '')): continue
        p = parse_addr_port(src.get('port'))
        if p: ports.append(p)
    p = parse_addr_port(data.get('local_port'))
    if p: ports.append(p)
    for key in ('listen', 'listen_addr'):
        v = data.get(key)
        if v and not is_local_bind(v):
            p = parse_addr_port(v)
            if p: ports.append(p)
    server = data.get('server', '')
    if isinstance(server, str) and not is_local_bind(server):
        p = parse_addr_port(server)
        if p: ports.append(p)
    return sorted(set(ports))

def extract_yaml(data):
    if not isinstance(data, dict): return []
    ports = []
    for key in ('listen', 'server', 'listen_addr'):
        v = data.get(key)
        if v and not is_local_bind(str(v)):
            p = parse_addr_port(v)
            if p: ports.append(p)
    for inb in (data.get('inbounds') or []):
        if not isinstance(inb, dict): continue
        for key in ('listen_port', 'port'):
            p = parse_addr_port(inb.get(key))
            if p: ports.append(p)
    return sorted(set(ports))

def strip_jsonc_comments(s):
    """状态机剥离 // 和 /* */ 注释，正确跳过字符串内容（URL中的//不受影响）"""
    out = []; i = 0; n = len(s); in_str = False
    while i < n:
        c = s[i]
        if in_str:
            if c == '\\' and i + 1 < n:
                out.append(c); out.append(s[i + 1]); i += 2; continue
            elif c == '"':
                in_str = False
            out.append(c)
        else:
            if c == '"':
                in_str = True; out.append(c)
            elif s[i:i+2] == '//':
                while i < n and s[i] != '\n': i += 1
                continue
            elif s[i:i+2] == '/*':
                end = s.find('*/', i + 2)
                i = (end + 2) if end != -1 else n
                continue
            else:
                out.append(c)
        i += 1
    return ''.join(out)

for f in sys.argv[1:]:
    try:
        ext = os.path.splitext(f)[1].lower()
        with open(f, encoding='utf-8', errors='ignore') as fp:
            content = fp.read()
        if ext in ('.yaml', '.yml') and HAS_YAML:
            data = yaml.safe_load(content)
            for p in extract_yaml(data): print(p)
        else:
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                data = json.loads(strip_jsonc_comments(content))
            for p in extract_json(data): print(p)
    except Exception:
        pass
PYEOF

    local cfg_files=()
    local cfg_dirs=(
        /usr/local/etc/xray    /etc/xray
        /usr/local/etc/v2ray   /etc/v2ray
        /etc/sing-box          /opt/sing-box     /usr/local/etc/sing-box
        /etc/hysteria          /etc/hysteria2
        /usr/local/etc/hysteria /usr/local/etc/hysteria2
        /etc/tuic              /usr/local/etc/tuic
        /etc/trojan            /etc/trojan-go
        /usr/local/etc/trojan  /usr/local/etc/trojan-go
        /etc/naiveproxy        /usr/local/etc/naive    /usr/local/etc/naiveproxy
        /etc/brook             /usr/local/etc/brook
        /etc/x-ui              /usr/local/x-ui/bin
        /opt/3x-ui             /opt/3x-ui/bin
        /opt/marzban
        /etc/amnezia           /etc/amneziawg
        /etc/gost              /usr/local/etc/gost
    )
    for d in "${cfg_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for pat in "config.json" "config.yaml" "config.yml" \
                   "server.json" "server.yaml" "server.yml" \
                   "*.json" "conf/*.json" "confs/*.json"; do
            for f in "${d}"/${pat}; do
                [[ -f "$f" ]] && cfg_files+=("$f")
            done
        done
    done
    for mz_cfg in /opt/marzban/xray_config.json /var/lib/marzban/xray_config.json; do
        [[ -f "$mz_cfg" ]] && cfg_files+=("$mz_cfg")
    done

    if [[ ${#cfg_files[@]} -gt 0 ]] && command -v python3 &>/dev/null; then
        while read -r port; do
            add_port "$port"
        done < <(python3 "$_PY_PARSER" "${cfg_files[@]}" 2>/dev/null | sort -un || true)
    elif [[ ${#cfg_files[@]} -gt 0 ]]; then
        warn "python3 未安装，跳过配置文件解析；仅依赖 ss 实时扫描结果"
    fi

    # ── 4. X-UI / 3x-ui SQLite 数据库读取 ───────────────────
    for db in /etc/x-ui/x-ui.db \
              /usr/local/x-ui/bin/x-ui.db \
              /opt/3x-ui/bin/x-ui.db \
              /usr/local/x-ui/x-ui.db; do
        [[ -f "$db" ]] || continue
        if command -v sqlite3 &>/dev/null; then
            while read -r xui_port; do
                [[ "$xui_port" =~ ^[0-9]+$ ]] && add_port "$xui_port"
            done < <(sqlite3 "$db" \
                "SELECT port FROM inbounds WHERE enable=1;" 2>/dev/null || true)
            ok "已从 X-UI 数据库读取启用节点端口: $db"
        else
            warn "检测到 X-UI 数据库: $db（sqlite3 缺失，跳过读取）"
            warn "★ 请确保所有 X-UI/3x-ui 节点处于【运行中】状态后再执行本脚本！"
        fi
    done

    # ── 5. Marzban 面板端口 ───────────────────────────────────
    if [[ -f /opt/marzban/.env || -f /etc/opt/marzban/.env ]]; then
        local mz_env="/opt/marzban/.env"
        [[ -f "$mz_env" ]] || mz_env="/etc/opt/marzban/.env"
        local mz_port
        # tr -d '[:space:]' 清除所有空白（含等号两侧空格/Tab）
        mz_port=$(grep -E '^UVICORN_PORT\s*=' "$mz_env" 2>/dev/null \
            | cut -d= -f2 | tr -d '[:space:]')
        if [[ -n "$mz_port" ]]; then
            add_port "$mz_port"
            info "Marzban 面板端口: $mz_port（已添加到放行列表）"
        fi
        warn "★ Marzban 节点端口存储在数据库，请确保所有节点处于【运行中】状态！"
    fi

    # ── 6. 233boy xray 文件名端口兜底 ────────────────────────
    local conf_dirs=(
        /etc/xray/conf /etc/xray/confs
        /usr/local/etc/xray/conf /usr/local/etc/xray/confs
    )
    for d in "${conf_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for f in "$d"/*.json; do
            [[ -f "$f" ]] || continue
            local fname_port
            fname_port=$(basename "$f" .json | grep -oE '^[0-9]+$' || true)
            [[ -z "$fname_port" ]] && \
                fname_port=$(basename "$f" | grep -oE '^[0-9]+' || true)
            [[ -n "$fname_port" ]] && add_port "$fname_port"
        done
    done
}

# ============================================================
# _get_docker_subnets: 获取所有 Docker 网络的 IPv4 子网
# ============================================================
_get_docker_subnets() {
    command -v docker &>/dev/null || return
    docker network ls --format '{{.ID}}' 2>/dev/null \
        | while read -r nid; do
            docker network inspect "$nid" \
                --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null
          done \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/' \
        | sort -u
}

# ============================================================
# build_nft_ruleset: 构建完整 nftables 规则集字符串（输出到 stdout）
#
# 架构说明：
#   table inet filter  — 统一 IPv4+IPv6 过滤（INPUT/FORWARD/OUTPUT）
#   table inet nat     — 统一 IPv4+IPv6 NAT
#     prerouting: redirect to :PORT（端口跳跃 Hysteria2）
#     postrouting: masquerade（Docker 容器出站 NAT）
#
# 端口跳跃使用 redirect 而非 dnat：
#   redirect 将流量重定向到本机同端口，天然支持双栈（IPv4+IPv6），
#   无需像 iptables 那样分别配置 DNAT 和 [::]:PORT
#
# SSH 防暴力破解使用 nftables meter：
#   meter 是 nftables 原生的 per-key 状态跟踪表，无需 xt_recent 模块
#   inet 表中需要分别用 ip saddr（IPv4）和 ip6 saddr（IPv6）作 key
# ============================================================
build_nft_ruleset() {
    # ── 构建 nftables 端口集合字符串 ────────────────────────
    # nftables 集合格式: { 80, 443, 8080 }  单个端口直接写: 443
    local port_set=""
    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        local joined
        joined=$(printf '%s, ' "${OPEN_PORTS[@]}")
        joined="${joined%, }"          # 去掉末尾 ", "
        if [[ ${#OPEN_PORTS[@]} -eq 1 ]]; then
            port_set="${OPEN_PORTS[0]}"
        else
            port_set="{ ${joined} }"
        fi
    fi

    # ── 构建跳跃范围的 INPUT 放行和 redirect 规则 ────────────
    local hop_input_rules=""
    local hop_redirect_rules=""
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            [[ -n "${HOP_S:-}" && -n "${HOP_E:-}" && -n "${HOP_T:-}" ]] || continue
            # INPUT: 跳跃范围端口必须放行（redirect 后包仍走 INPUT）
            hop_input_rules+="        tcp dport ${HOP_S}-${HOP_E} accept\n"
            hop_input_rules+="        udp dport ${HOP_S}-${HOP_E} accept\n"
            # NAT prerouting: redirect to :PORT
            # redirect 自动保留目标 IP，只改目标端口，同时支持 IPv4 和 IPv6
            hop_redirect_rules+="        udp dport ${HOP_S}-${HOP_E} redirect to :${HOP_T}\n"
            hop_redirect_rules+="        tcp dport ${HOP_S}-${HOP_E} redirect to :${HOP_T}\n"
        done
    fi

    # ── 构建 Docker 相关规则 ─────────────────────────────────
    local docker_forward_rules=""
    local docker_masq_rules=""
    if [[ $_DOCKER_RUNNING -eq 1 ]]; then
        # FORWARD: 允许 docker0 出入流量（容器间/容器→外网）
        docker_forward_rules="        # Docker 容器网络转发\n"
        docker_forward_rules+="        meta iifname \"docker0\" accept\n"
        docker_forward_rules+="        meta oifname \"docker0\" ct state { established, related } accept\n"

        # postrouting masquerade：为每个 Docker 子网生成一条规则
        local subnets
        mapfile -t subnets < <(_get_docker_subnets)
        if [[ ${#subnets[@]} -gt 0 ]]; then
            docker_masq_rules="        # Docker 出站 masquerade\n"
            for subnet in "${subnets[@]}"; do
                docker_masq_rules+="        ip saddr ${subnet} masquerade\n"
            done
        else
            # 兜底：docker0 默认子网
            docker_masq_rules="        # Docker 出站 masquerade（默认 bridge 子网）\n"
            docker_masq_rules+="        ip saddr 172.17.0.0/16 masquerade\n"
        fi
    fi

    # ═══════════════════════════════════════════════════════════
    # 输出完整规则集
    # ═══════════════════════════════════════════════════════════
    cat << NFT_EOF
#!/usr/sbin/nft -f
# ─────────────────────────────────────────────────────────────
# port.sh v${VERSION} — nftables 规则集
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 警告: 此文件由脚本自动生成，重启后由 nftables.service 加载
#       手动修改将在下次运行 port.sh 时被覆盖
# ─────────────────────────────────────────────────────────────

flush ruleset

# ═════════════════════════════════════════════════════════════
# 过滤表（inet = IPv4 + IPv6 统一，无需 iptables + ip6tables）
# ═════════════════════════════════════════════════════════════
table inet filter {

    chain input {
        type filter hook input priority 0; policy drop;

        # 回环接口全放行
        iif "lo" accept

        # 丢弃无效连接追踪包（防端口扫描/伪造包）
        ct state invalid drop

        # 已建立的连接放行
        ct state { established, related } accept

        # ── ICMPv4 ──────────────────────────────────────────
        # ping 限速放行（防 ICMP 洪泛），其余 ICMPv4 全丢弃
        ip protocol icmp icmp type echo-request \\
            limit rate 5/second burst 10 packets accept
        ip protocol icmp drop

        # ── ICMPv6（甲骨文云 ARM / 所有 IPv6 环境必须放行）──
        # NDP（邻居发现协议）是 IPv6 正常工作的基础，缺一不可：
        #   nd-neighbor-solicit/advert: 地址解析（相当于 IPv4 ARP）
        #   nd-router-solicit/advert:   路由发现（默认网关）
        #   nd-redirect:                重定向优化
        icmpv6 type {
            nd-neighbor-solicit, nd-neighbor-advert,
            nd-router-solicit,   nd-router-advert,
            nd-redirect
        } accept
        # ICMPv6 ping 限速放行
        icmpv6 type echo-request \\
            limit rate 5/second burst 10 packets accept
        # 其余 ICMPv6 丢弃（不能全 DROP，上面已放行关键类型）
        meta l4proto ipv6-icmp drop

        # ── SSH 防暴力破解（nftables meter，per-IP 令牌桶）──
        # meter 是 nftables 原生 per-key 状态表：
        #   - 每个源 IP 独立计速（比 iptables recent 模块更精准）
        #   - 60 秒窗口内超过 10 次新连接则封锁该 IP
        #   - 无需加载额外内核模块（xt_recent）
        tcp dport ${SSH_PORT} ct state new \\
            meter ssh4 { ip saddr timeout 60s \\
                limit rate over 10/minute burst 10 packets } drop
        tcp dport ${SSH_PORT} ct state new \\
            meter ssh6 { ip6 saddr timeout 60s \\
                limit rate over 10/minute burst 10 packets } drop
        tcp dport ${SSH_PORT} accept
NFT_EOF

    # 开放代理端口（仅在有端口时输出）
    if [[ -n "$port_set" ]]; then
        cat << NFT_EOF

        # ── 开放代理端口 ─────────────────────────────────────
        tcp dport ${port_set} accept
        udp dport ${port_set} accept
NFT_EOF
    fi

    # 端口跳跃 INPUT 放行（仅在有跳跃规则时输出）
    if [[ -n "$hop_input_rules" ]]; then
        cat << NFT_EOF

        # ── 端口跳跃范围放行（redirect 后包仍走 INPUT 链）───
NFT_EOF
        printf "%b" "$hop_input_rules"
    fi

    cat << NFT_EOF

        # ── 限速日志丢弃（排查被拦截连接）──────────────────
        limit rate 5/minute log prefix "[FW-DROP] " level warn
        drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;

        # 已建立的转发连接放行（NAT 回程包 / VPN 转发）
        ct state { established, related } accept
NFT_EOF

    if [[ -n "$docker_forward_rules" ]]; then
        echo ""
        printf "%b" "$docker_forward_rules"
    fi

    cat << NFT_EOF
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}

# ═════════════════════════════════════════════════════════════
# NAT 表（inet = IPv4+IPv6 统一，需内核 ≥ 5.2）
#   Ubuntu 22.04 = 5.15 LTS ✓   Ubuntu 24.04 = 6.8+ ✓
# ═════════════════════════════════════════════════════════════
table inet nat {

    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;

        # ── 端口跳跃（Hysteria2 H2 协议）────────────────────
        # redirect to :PORT 将外部端口流量重定向到本机指定端口
        # 比 iptables DNAT 更简洁：单条规则同时覆盖 IPv4 和 IPv6
        # 不需要像 iptables 那样分别写 0.0.0.0:PORT 和 [::]:PORT
NFT_EOF

    if [[ -n "$hop_redirect_rules" ]]; then
        printf "%b" "$hop_redirect_rules"
    else
        echo "        # （暂无端口跳跃规则，如需添加: bash port.sh --add-hop）"
    fi

    cat << NFT_EOF
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;

NFT_EOF

    if [[ -n "$docker_masq_rules" ]]; then
        printf "%b" "$docker_masq_rules"
    else
        echo "        # （无 Docker 或未检测到容器网络）"
    fi

    cat << NFT_EOF
    }
}
NFT_EOF
}

# ============================================================
# apply_rules: 原子加载完整 nftables 规则集
# ============================================================
apply_rules() {
    if [[ "$DRY_RUN" == true ]]; then
        info "[预览] 即将加载的 nftables 规则集:"
        hr
        build_nft_ruleset
        hr
        return 0
    fi

    # ── 检测 Docker（在 flush 之前，否则 docker info 可能超时）─
    _DOCKER_RUNNING=0
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        _DOCKER_RUNNING=1
        warn "检测到 Docker 正在运行，配置 nftables 接管容器网络..."

        # 设置 Docker daemon.json iptables=false
        # Docker 将不再自行管理 iptables/nftables 规则，由本脚本统一管理
        local daemon_json="/etc/docker/daemon.json"
        if command -v python3 &>/dev/null; then
            python3 - "$daemon_json" << 'PYEOF' 2>/dev/null && \
                ok "Docker daemon.json: iptables=false 已设置" || true
import json, sys, os

path = sys.argv[1]
try:
    with open(path) as f:
        d = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    d = {}

if d.get('iptables') is False:
    sys.exit(0)  # 已经设置过，无需修改

d['iptables'] = False
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, 'w') as f:
    json.dump(d, f, indent=2)
    f.write('\n')
print("done")
PYEOF
        else
            # python3 缺失时的简单写法（会覆盖已有内容，仅作兜底）
            if [[ ! -f "$daemon_json" ]]; then
                echo '{"iptables": false}' > "$daemon_json"
                ok "Docker daemon.json: 已创建并设置 iptables=false"
            fi
        fi
    fi

    # ── 构建规则集并原子加载 ─────────────────────────────────
    info "构建 nftables 规则集..."
    _NFT_TMPFILE=$(mktemp /tmp/_nft_rules_XXXXXX.nft)
    build_nft_ruleset > "$_NFT_TMPFILE"

    # nft -c: 检查模式（dry-run），不实际加载
    if ! nft -c -f "$_NFT_TMPFILE" 2>/dev/null; then
        warn "规则集语法检查失败，详情："
        nft -c -f "$_NFT_TMPFILE" 2>&1 | head -10 || true
        err "nftables 规则集语法错误，请检查内核版本（需要 ≥ 5.2 支持 inet NAT）"
    fi

    # nft -f: 原子加载（包含 flush ruleset，一次性替换所有规则）
    if nft -f "$_NFT_TMPFILE" 2>/dev/null; then
        ok "nftables 规则集已原子性加载"
    else
        nft -f "$_NFT_TMPFILE" 2>&1 | head -5 || true
        err "nftables 规则集加载失败"
    fi

    # ── Docker 重启：重建容器网络（nftables 接管后必须重启）──
    if [[ $_DOCKER_RUNNING -eq 1 ]]; then
        info "重启 Docker 以重建容器网络（nftables 接管后必须重启）..."
        systemctl restart docker 2>/dev/null \
            || service docker restart 2>/dev/null \
            || true
        ok "Docker 已重启，容器网络由 nftables masquerade 接管"
    fi
}

# ============================================================
# save_rules: 持久化 nftables 规则到 /etc/nftables.conf
# 启用 nftables.service，重启后自动加载
# ============================================================
save_rules() {
    [[ "$DRY_RUN" == true ]] && return 0

    # 将当前已加载的 ruleset dump 到配置文件
    # 使用 build_nft_ruleset 而非 nft list ruleset，保留注释和结构
    build_nft_ruleset > /etc/nftables.conf

    # 启用 nftables 系统服务（Ubuntu 22.04/24.04 默认已安装）
    systemctl enable nftables 2>/dev/null || true
    # 验证服务可以正常加载当前配置
    systemctl restart nftables 2>/dev/null || true

    ok "规则已保存至 /etc/nftables.conf，重启后由 nftables.service 自动加载"
}

# ============================================================
# show_status: 显示防火墙当前状态
# ============================================================
show_status() {
    hr; echo -e "${C}防火墙当前状态 (port.sh v${VERSION} · nftables)${W}"; hr

    echo -e "${G}▸ nftables 服务状态:${W}"
    printf "  • %-20s %s\n" "nftables.service:" \
        "$(systemctl is-active nftables 2>/dev/null || echo '未运行')"

    echo -e "\n${G}▸ 当前加载的端口跳跃（prerouting redirect）:${W}"
    local has_hop=0
    while IFS= read -r line; do
        if [[ "$line" =~ udp[[:space:]]+dport[[:space:]]+([0-9]+)-([0-9]+).*redirect.*:([0-9]+) ]]; then
            echo "  • UDP+TCP ${BASH_REMATCH[1]}-${BASH_REMATCH[2]} → :${BASH_REMATCH[3]}"
            has_hop=1
        fi
    done < <(nft list table inet nat 2>/dev/null || true)
    [[ $has_hop -eq 0 ]] && echo "  （无端口跳跃规则）"

    echo -e "\n${G}▸ 当前开放端口（filter input accept）:${W}"
    nft list chain inet filter input 2>/dev/null \
        | grep -E 'dport.*accept' \
        | grep -v 'redirect\|meter\|SSH\|ssh' \
        | sed 's/^[[:space:]]*/  • /' || echo "  （无）"

    echo -e "\n${G}▸ 公网实时监听端口（ss -tulnp）:${W}"
    while read -r p; do
        local proc
        proc=$(ss -tulnp 2>/dev/null | grep ":${p}[^0-9]" \
            | grep -oE '"[^"]+"' | head -1 | tr -d '"')
        printf "  • %-6s %s\n" "$p" "${proc:-(未知进程)}"
    done < <(get_public_ports)

    echo -e "\n${G}▸ 关键 sysctl 参数:${W}"
    for param in \
        net.ipv4.ip_forward \
        net.ipv6.conf.all.forwarding \
        net.ipv4.tcp_timestamps \
        net.ipv4.conf.all.rp_filter; do
        printf "  • %-45s = %s\n" "$param" \
            "$(sysctl -n "$param" 2>/dev/null || echo '未知')"
    done

    echo -e "\n${G}▸ 防火墙前端状态（应全部为非运行）:${W}"
    for svc in firewalld ufw iptables ip6tables; do
        printf "  • %-20s %s\n" "${svc}:" \
            "$(systemctl is-active "$svc" 2>/dev/null || echo '未运行/已禁用')"
    done
    if command -v docker &>/dev/null; then
        printf "  • %-20s %s\n" "docker:" \
            "$(systemctl is-active docker 2>/dev/null || echo '未知')"
        # 检查 Docker daemon.json iptables 配置
        if command -v python3 &>/dev/null && [[ -f /etc/docker/daemon.json ]]; then
            local ipt_setting
            ipt_setting=$(python3 -c \
                "import json; d=json.load(open('/etc/docker/daemon.json')); \
                 print('false ✓' if d.get('iptables') is False else 'true ⚠（未禁用）')" \
                2>/dev/null || echo "未知")
            printf "  • %-20s %s\n" "docker iptables=" "$ipt_setting"
        fi
    fi

    echo -e "\n${G}▸ 完整 nftables 规则集:${W}"
    nft list ruleset 2>/dev/null || echo "  （无规则或 nftables 未运行）"
    hr
}

# ============================================================
# reset_fw: 重置防火墙为全部放行（flush ruleset）
# ============================================================
reset_fw() {
    echo -e "${R}⚠  将清除所有 nftables 规则并全部放行，确认？[y/N]${W}"
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { info "已取消"; exit 0; }

    nft flush ruleset 2>/dev/null || true
    ok "nftables 规则集已清空（全部放行）"

    # 保存空规则集
    {
        echo "#!/usr/sbin/nft -f"
        echo "# port.sh v${VERSION} — 已重置为全部放行"
        echo "# $(date '+%Y-%m-%d %H:%M:%S')"
        echo "flush ruleset"
    } > /etc/nftables.conf

    systemctl restart nftables 2>/dev/null || true
    ok "空规则集已保存至 /etc/nftables.conf（重启后仍全部放行）"
    warn "如需重新配置防火墙: bash port.sh"
}

# ============================================================
# add_hop_interactive: 手动交互式添加端口跳跃
# 采用增量方式（nft add rule），无需重新扫描端口
# ============================================================
add_hop_interactive() {
    detect_ssh
    hr; echo -e "${C}手动添加 Hysteria2 端口跳跃规则（nftables redirect）${W}"; hr
    echo -e "${Y}说明: 端口跳跃将多个外部端口的流量 redirect 到代理实际监听端口${W}"
    echo -e "${Y}示例: 外部 20000-50000 → 内部 :443（同时覆盖 IPv4 和 IPv6）${W}"
    echo
    read -rp "跳跃端口范围（如 20000-50000）: " hop_range
    read -rp "目标端口（代理实际监听端口，如 443）: " target_port

    [[ "$hop_range"   =~ ^[0-9]+-[0-9]+$ ]] \
        || err "范围格式错误，示例: 20000-50000"
    [[ "$target_port" =~ ^[0-9]+$         ]] \
        || err "目标端口格式错误，必须是数字"
    [[ "$target_port" -ge 1 && "$target_port" -le 65535 ]] \
        || err "目标端口超出范围 (1-65535)"

    local s e
    s=$(echo "$hop_range" | cut -d- -f1)
    e=$(echo "$hop_range" | cut -d- -f2)
    [[ "$s" -lt "$e" ]] || err "起始端口必须小于结束端口"
    [[ "$s" -ge 1024  ]] || warn "起始端口 < 1024，可能与系统端口冲突"

    # 检查 nftables 表是否已存在（防止 add rule 到不存在的表）
    if ! nft list table inet filter &>/dev/null 2>&1; then
        err "未检测到 nftables 规则集，请先运行 bash port.sh 进行初始配置"
    fi
    if ! nft list table inet nat &>/dev/null 2>&1; then
        err "未检测到 nftables nat 表，请先运行 bash port.sh 进行初始配置"
    fi

    # ── 增量添加规则（不影响现有规则集）────────────────────
    # INPUT：端口跳跃范围必须放行（redirect 后包走 INPUT 而非 FORWARD）
    # 规则插入到 drop 规则之前（用 position 或在 log 规则前插入）
    nft insert rule inet filter input tcp dport "${s}-${e}" accept 2>/dev/null || true
    nft insert rule inet filter input udp dport "${s}-${e}" accept 2>/dev/null || true

    # NAT prerouting：redirect 同时处理 IPv4 和 IPv6
    nft add rule inet nat prerouting \
        udp dport "${s}-${e}" redirect to ":${target_port}" 2>/dev/null || true
    nft add rule inet nat prerouting \
        tcp dport "${s}-${e}" redirect to ":${target_port}" 2>/dev/null || true

    ok "端口跳跃规则已添加到运行中的 nftables"

    # 将当前完整 ruleset 持久化（包含新增的跳跃规则）
    nft list ruleset > /tmp/_nft_current_rules.nft 2>/dev/null || true
    {
        echo "#!/usr/sbin/nft -f"
        printf "# port.sh v%s — 含手动添加跳跃规则 %s → %s\n" \
            "$VERSION" "$hop_range" "$target_port"
        echo "# $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        cat /tmp/_nft_current_rules.nft
    } > /etc/nftables.conf
    rm -f /tmp/_nft_current_rules.nft

    systemctl restart nftables 2>/dev/null || true
    ok "端口跳跃 ${hop_range} → ${target_port} 添加并持久化完成"
    echo
    echo -e "${C}验证命令:${W}"
    echo "  nft list table inet nat          # 查看 redirect 规则"
    echo "  nft list table inet filter       # 查看 INPUT 放行规则"
}

# ============================================================
# show_summary: 最终汇总输出
# ============================================================
show_summary() {
    hr; echo -e "${G}🎉 防火墙配置完成！（port.sh v${VERSION} · nftables）${W}"; hr

    echo -e "${C}SSH 端口  :${W} $SSH_PORT  ${Y}（防暴力破解: per-IP 60秒内限10次连接）${W}"
    echo -e "${C}开放端口  :${W} ${OPEN_PORTS[*]:-（无）}"

    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        echo -e "${C}端口跳跃  :${W}"
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            echo -e "  ${G}•${W} UDP+TCP ${HOP_S}-${HOP_E} → :${HOP_T}  ${C}（nftables redirect，IPv4+IPv6 双栈）${W}"
        done
    else
        warn "未检测到端口跳跃配置（Hysteria2 需要）"
        echo -e "  ${Y}如需手动添加: bash port.sh --add-hop${W}"
    fi

    hr
    echo -e "${Y}⚠  重要提示：${W}"
    echo -e "  ${R}▸ 云平台安全组（本机防火墙只是第一层）：${W}"
    echo    "    甲骨文: VCN → 安全列表 / NSG 入站规则"
    echo    "    AWS:    EC2 安全组 → Inbound Rules"
    echo    "    阿里云 / 腾讯云: 安全组规则"
    echo    "    以上需在云控制台单独放行端口，否则流量到达不了本机！"
    echo
    echo -e "  ${Y}▸ 面板管理端口安全建议：${W}"
    echo    "    X-UI (54321) / 3x-ui 面板建议通过 SSH 隧道访问："
    echo    "    ssh -L 54321:127.0.0.1:54321 root@服务器IP"
    echo    "    然后访问 http://127.0.0.1:54321（本地安全访问）"
    echo
    echo -e "  ${G}▸ nftables 已接管防火墙，iptables 服务已全部禁用/屏蔽${W}"
    echo -e "  ${G}▸ IPv4 + IPv6 双栈由单一 inet 表统一管理${W}"
    if [[ $_DOCKER_RUNNING -eq 1 ]]; then
        echo -e "  ${G}▸ Docker daemon.json iptables=false 已设置，Docker 已重启${W}"
        echo -e "  ${G}▸ 容器出站 masquerade 由 nftables postrouting 接管${W}"
    fi

    hr
    echo -e "${Y}常用命令:${W}"
    echo "  查看状态       : bash port.sh --status"
    echo "  手动加跳跃     : bash port.sh --add-hop"
    echo "  重置防火墙     : bash port.sh --reset"
    echo "  预览不改动     : bash port.sh --dry-run"
    echo "  查看规则集     : nft list ruleset"
    echo "  查看过滤规则   : nft list table inet filter"
    echo "  查看 NAT 规则  : nft list table inet nat"
    echo "  查看统计数据   : nft list ruleset -a"
    hr
}

# ============================================================
# main
# ============================================================
main() {
    echo -e "${B}══════════════════════════════════════════${W}"
    echo -e "${G}    代理节点防火墙管理脚本 v${VERSION}（nftables）${W}"
    echo -e "${B}══════════════════════════════════════════${W}"

    # ── 单功能模式 ──────────────────────────────────────────
    [[ $_status -eq 1 ]] && { detect_ssh; show_status;  exit 0; }
    [[ $_reset  -eq 1 ]] && { detect_ssh; reset_fw;     exit 0; }
    [[ $_addhop -eq 1 ]] && { add_hop_interactive;      exit 0; }

    # ── 主流程 ─────────────────────────────────────────────
    install_deps
    detect_ssh

    # ① 先读取已有跳跃规则（add_port 会排除跳跃范围内的端口）
    detect_existing_hop_rules
    detect_hysteria_hop

    # ② 综合扫描端口（ss + 配置文件 + 数据库）
    detect_ports

    # 确保 80/443 始终开放
    add_port 80
    add_port 443

    # 排序去重
    if [[ ${#OPEN_PORTS[@]} -gt 0 ]]; then
        mapfile -t OPEN_PORTS < <(printf '%s\n' "${OPEN_PORTS[@]}" | sort -un) || true
    fi

    # ── 预览摘要 ─────────────────────────────────────────────
    echo
    info "即将开放端口  : ${OPEN_PORTS[*]:-（无）}"
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            info "端口跳跃配置  : ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
    else
        warn "未检测到端口跳跃配置，如需手动添加: bash port.sh --add-hop"
    fi
    echo

    # ── 应用规则（原子加载）─────────────────────────────────
    apply_rules
    save_rules
    show_summary
}

main "$@"

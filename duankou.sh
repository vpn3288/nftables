#!/bin/bash
# ============================================================
# nftables 防火墙管理脚本 v4.0
# 适用于 Xray / Sing-box / V2Ray / Hysteria2 等代理服务
# 支持 Ubuntu 22/24, Debian 11/12, CentOS/RHEL 8+
# 功能：自动端口检测 | SSH防暴力 | 端口跳跃NAT | 持久化
# ============================================================
set -uo pipefail

# ── 颜色 ────────────────────────────────────────────────────
R="\033[31m" Y="\033[33m" G="\033[32m" C="\033[36m" B="\033[34m" W="\033[0m"
ok()   { echo -e "${G}✓ $*${W}"; }
warn() { echo -e "${Y}⚠ $*${W}"; }
err()  { echo -e "${R}✗ $*${W}"; exit 1; }
info() { echo -e "${C}→ $*${W}"; }
hr()   { echo -e "${B}──────────────────────────────────────────${W}"; }

[[ $(id -u) -eq 0 ]] || err "需要 root 权限"

# ── 全局变量 ────────────────────────────────────────────────
VERSION="4.0"
SSH_PORT=""
OPEN_PORTS=()
HOP_RULES=()   # 格式: "起始-结束->目标"  如 "20000-50000->443"
DRY_RUN=false
NFT_TABLE="proxy_firewall"
NFT_CONF="/etc/nftables.conf"

EXCLUDE_PROCS="cloudflared|chronyd|dnsmasq|systemd-resolve|named|unbound|ntpd|avahi"

BLACKLIST_PORTS=(23 25 53 69 111 135 137 138 139 445 514 631
    110 143 465 587 993 995
    1433 1521 3306 5432 6379 27017
    3389 5900 5901 5902 323 2049
    8181 9090 3000 3001 8000 8001 54321 62789
    10080 10081 10082 10083 10084 10085 10086)

# ── 参数解析 ────────────────────────────────────────────────
_status=0 _reset=0 _addhop=0
for arg in "$@"; do case "$arg" in
    --dry-run)  DRY_RUN=true ;;
    --status)   _status=1 ;;
    --reset)    _reset=1 ;;
    --add-hop)  _addhop=1 ;;
    --help|-h)
        echo "用法: bash nftables_fw.sh [--dry-run|--status|--reset|--add-hop|--help]"
        echo "  (无参数)   交互式完整配置"
        echo "  --status   查看当前规则和端口"
        echo "  --reset    清空所有规则（全部放行）"
        echo "  --add-hop  手动添加端口跳跃规则"
        echo "  --dry-run  预览模式，不实际修改"
        exit 0 ;;
    *) err "未知参数: $arg" ;;
esac; done

# ============================================================
# 工具函数
# ============================================================

get_public_ports() {
    ss -tulnp 2>/dev/null \
        | grep -vE '[[:space:]](127\.|::1)[^[:space:]]' \
        | grep -vE "($EXCLUDE_PROCS)" \
        | grep -oE '(\*|0\.0\.0\.0|\[?::\]?):[0-9]+' \
        | grep -oE '[0-9]+$' \
        | while read -r p; do [[ "$p" -lt 32768 ]] && echo "$p" || true; done \
        | sort -un || true
}

parse_hop() {
    local rule=$1
    HOP_S=$(echo "$rule" | cut -d'-' -f1)
    HOP_E=$(echo "$rule" | cut -d'-' -f2 | cut -d'>' -f1 | tr -d '>')
    HOP_T=$(echo "$rule" | grep -oE '[0-9]+$')
}

port_in_hop_range() {
    local p=$1
    for rule in "${HOP_RULES[@]:-}"; do
        [[ -z "$rule" ]] && continue
        parse_hop "$rule"
        [[ "$p" -ge "$HOP_S" && "$p" -le "$HOP_E" ]] && return 0
    done
    return 1
}

is_blacklisted() {
    local p=$1
    [[ "$p" == "$SSH_PORT" ]] && return 0
    for b in "${BLACKLIST_PORTS[@]}"; do [[ "$p" == "$b" ]] && return 0; done
    return 1
}

add_port() {
    local p=$1
    [[ "$p" =~ ^[0-9]+$ ]]             || return 0
    [[ "$p" -ge 1 && "$p" -le 65535 ]] || return 0
    is_blacklisted "$p"                 && return 0
    port_in_hop_range "$p"             && return 0
    [[ " ${OPEN_PORTS[*]:-} " =~ " $p " ]] && return 0
    OPEN_PORTS+=("$p")
}

# ============================================================
# 初始化
# ============================================================
install_deps() {
    info "检查依赖..."
    if ! command -v nft &>/dev/null; then
        info "安装 nftables..."
        command -v apt-get &>/dev/null && apt-get install -y -qq nftables iproute2 || true
        command -v dnf     &>/dev/null && dnf install -y nftables iproute           || true
        command -v yum     &>/dev/null && yum install -y nftables iproute            || true
        command -v nft &>/dev/null || err "nftables 安装失败，请手动安装"
    fi

    # 禁用冲突防火墙
    for svc in ufw firewalld netfilter-persistent iptables ip6tables; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
            systemctl stop    "$svc" &>/dev/null || true
            systemctl disable "$svc" &>/dev/null || true
            systemctl mask    "$svc" &>/dev/null || true
        fi
    done

    # 清空残留 iptables
    if command -v iptables &>/dev/null; then
        for t in filter nat mangle raw; do
            iptables  -t "$t" -F &>/dev/null || true
            ip6tables -t "$t" -F &>/dev/null || true
        done
        iptables  -P INPUT   ACCEPT &>/dev/null || true
        iptables  -P FORWARD ACCEPT &>/dev/null || true
        ip6tables -P INPUT   ACCEPT &>/dev/null || true
        ip6tables -P FORWARD ACCEPT &>/dev/null || true
    fi

    # sysctl：ip_forward + rp_filter=2（宽松，兼容端口跳跃UDP）
    cat > /etc/sysctl.d/98-nftables-fw.conf << 'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.tcp_timestamps=0
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.default.rp_filter=2
EOF
    sysctl -p /etc/sysctl.d/98-nftables-fw.conf &>/dev/null || true
    ok "依赖检查完成"
}

detect_ssh() {
    SSH_PORT=$(ss -tlnp 2>/dev/null | grep sshd | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=$(awk '/^Port /{print $2;exit}' /etc/ssh/sshd_config 2>/dev/null || true)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    ok "SSH 端口: $SSH_PORT"
}

# ============================================================
# 端口跳跃检测
# ============================================================
detect_existing_hop_rules() {
    while IFS= read -r line; do
        local s e t
        s=$(echo "$line" | grep -oE 'dport [0-9]+-[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
        e=$(echo "$line" | grep -oE 'dport [0-9]+-[0-9]+' | grep -oE '[0-9]+' | tail -1 || true)
        t=$(echo "$line" | grep -oE 'dnat to :[0-9]+' | grep -oE '[0-9]+' || true)
        local rule="${s}-${e}->${t}"
        [[ -n "$s" && -n "$e" && -n "$t" ]] || continue
        [[ " ${HOP_RULES[*]:-} " =~ " ${rule} " ]] || HOP_RULES+=("$rule")
    done < <(nft list table inet "$NFT_TABLE" 2>/dev/null | grep "dnat to" || true)
}

detect_hysteria_hop() {
    local dirs=(/etc/hysteria /etc/hysteria2 /usr/local/etc/hysteria)
    for d in "${dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for ext in json yaml yml; do
            local f="${d}/config.${ext}"
            [[ -f "$f" ]] || continue
            local listen_port="" hop_range=""
            if [[ "$ext" == "json" ]]; then
                listen_port=$(grep -oE '"listen"[^:]*:[^"]*":[0-9]+"' "$f" 2>/dev/null \
                    | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
                hop_range=$(grep -oE '"(portHopping|portRange)"[^:]*:"[0-9]+-[0-9]+"' "$f" 2>/dev/null \
                    | grep -oE '[0-9]+-[0-9]+' | head -1 || true)
            else
                listen_port=$(grep -E '^\s*listen\s*:' "$f" 2>/dev/null \
                    | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | head -1 || true)
                hop_range=$(grep -E '^\s*(portHopping|portRange)\s*:' "$f" 2>/dev/null \
                    | grep -oE '[0-9]+-[0-9]+' | head -1 || true)
            fi
            if [[ -n "$listen_port" && -n "$hop_range" ]]; then
                local rule="${hop_range}->${listen_port}"
                [[ " ${HOP_RULES[*]:-} " =~ " ${rule} " ]] \
                    || { HOP_RULES+=("$rule"); ok "检测到 Hysteria2 跳跃: $hop_range → $listen_port"; }
            fi
        done
    done
}

# ============================================================
# 端口检测：ss为主 + 配置文件补充
# ============================================================
detect_ports() {
    info "扫描公网监听端口..."

    while read -r port; do add_port "$port"; done < <(get_public_ports)

    # Python 解析 JSON 配置文件
    local py_parser="/tmp/_fw_parse_ports.py"
    cat > "$py_parser" << 'PYEOF'
import json, sys
def extract(data):
    ports, LOCAL = [], ('127.','::1','localhost')
    is_local = lambda v: any(str(v or '').startswith(x) for x in LOCAL)
    for inb in (data.get('inbounds') or []):
        if not isinstance(inb, dict): continue
        for key in ('port','listen_port'):
            p = inb.get(key)
            if isinstance(p,int) and 1<=p<=65535 and not is_local(inb.get('listen','')):
                ports.append(p)
    for src in [data.get('inbound')] + list(data.get('inboundDetour') or []):
        if not isinstance(src, dict): continue
        p = src.get('port')
        if isinstance(p,int) and 1<=p<=65535 and not is_local(src.get('listen','')):
            ports.append(p)
    return sorted(set(ports))
for f in sys.argv[1:]:
    try:
        with open(f) as fp: [print(p) for p in extract(json.load(fp))]
    except: pass
PYEOF

    local cfg_files=()
    local cfg_dirs=(
        /usr/local/etc/xray /etc/xray
        /usr/local/etc/v2ray /etc/v2ray
        /etc/sing-box /opt/sing-box /usr/local/etc/sing-box
        /etc/v2ray-agent/xray/conf /etc/v2ray-agent/sing-box/conf
        /etc/hysteria /etc/hysteria2 /etc/tuic /etc/trojan
        /etc/x-ui /opt/3x-ui/bin /usr/local/x-ui/bin
    )
    for d in "${cfg_dirs[@]}"; do
        [[ -d "$d" ]] || continue
        for f in "$d"/config.json "$d"/*.json "$d"/conf/*.json; do
            [[ -f "$f" ]] && cfg_files+=("$f")
        done
    done

    if [[ ${#cfg_files[@]} -gt 0 ]]; then
        while read -r port; do add_port "$port"
        done < <(python3 "$py_parser" "${cfg_files[@]}" 2>/dev/null | sort -un || true)
    fi

    # 233boy / v2ray-agent 文件名端口兜底
    for d in /etc/xray/conf /usr/local/etc/xray/conf /etc/v2ray-agent/xray/conf; do
        [[ -d "$d" ]] || continue
        for f in "$d"/*.json; do
            [[ -f "$f" ]] || continue
            local fname_port
            fname_port=$(basename "$f" | grep -oE '^[0-9]+' || true)
            [[ -n "$fname_port" ]] && add_port "$fname_port"
        done
    done
}

# ============================================================
# 应用 nftables 规则
# ============================================================
apply_rules() {
    local unique_ports=()
    mapfile -t unique_ports < <(printf '%s\n' "${OPEN_PORTS[@]:-}" | sort -un) || true

    if [[ "$DRY_RUN" == true ]]; then
        hr; info "[预览模式] 以下规则不会实际应用"
        info "SSH 端口 : $SSH_PORT"
        info "开放端口 : ${unique_ports[*]:-无}"
        for rule in "${HOP_RULES[@]:-}"; do
            [[ -z "$rule" ]] && continue
            parse_hop "$rule"; info "端口跳跃 : ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
        hr; return 0
    fi

    info "应用 nftables 规则..."
    nft flush ruleset 2>/dev/null || true

    local port_list=""
    [[ ${#unique_ports[@]} -gt 0 ]] && port_list=$(IFS=','; echo "${unique_ports[*]}")

    local hop_input="" hop_nat=""
    for rule in "${HOP_RULES[@]:-}"; do
        [[ -z "$rule" ]] && continue
        parse_hop "$rule"
        [[ -z "${HOP_S:-}" || -z "${HOP_E:-}" || -z "${HOP_T:-}" ]] && continue
        hop_input+="        tcp dport ${HOP_S}-${HOP_E} accept\n"
        hop_input+="        udp dport ${HOP_S}-${HOP_E} accept\n"
        hop_nat+="        tcp dport ${HOP_S}-${HOP_E} dnat to :${HOP_T}\n"
        hop_nat+="        udp dport ${HOP_S}-${HOP_E} dnat to :${HOP_T}\n"
    done

    {
        cat << HEADER
table inet ${NFT_TABLE} {

    chain input_chain {
        type filter hook input priority filter; policy drop;

        iif "lo" accept
        ct state established,related accept
        icmp  type echo-request limit rate 10/second burst 5 packets accept
        icmpv6 type echo-request limit rate 10/second burst 5 packets accept

        # SSH 防暴力破解
        tcp dport ${SSH_PORT} ct state new limit rate 4/minute burst 4 packets accept
        tcp dport ${SSH_PORT} ct state new drop
        tcp dport ${SSH_PORT} accept
HEADER

        if [[ -n "$port_list" ]]; then
            echo ""
            echo "        # 代理端口"
            echo "        tcp dport { ${port_list} } accept"
            echo "        udp dport { ${port_list} } accept"
        fi

        if [[ -n "$hop_input" ]]; then
            echo ""
            echo "        # 端口跳跃范围放行"
            printf "%b" "$hop_input"
        fi

        cat << MIDDLE

        limit rate 5/minute log prefix "nft-drop: " level warn
    }

    chain forward_chain {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        ct state dnat accept
    }

    chain output_chain {
        type filter hook output priority filter; policy accept;
    }
MIDDLE

        if [[ -n "$hop_nat" ]]; then
            echo ""
            echo "    chain prerouting_chain {"
            echo "        type nat hook prerouting priority dstnat; policy accept;"
            printf "%b" "$hop_nat"
            echo "    }"
        fi

        echo "}"
    } | nft -f - || err "nftables 规则应用失败，请检查语法"

    ok "nftables 规则已应用"
}

# ============================================================
# 持久化
# ============================================================
save_rules() {
    [[ "$DRY_RUN" == true ]] && return 0
    nft list ruleset > "$NFT_CONF"
    systemctl unmask  nftables &>/dev/null || true
    systemctl enable  nftables &>/dev/null || true
    systemctl restart nftables &>/dev/null || true
    systemctl is-active --quiet nftables \
        && ok "规则已保存至 $NFT_CONF，nftables 开机自启已启用" \
        || warn "nftables 服务状态异常: systemctl status nftables"
}

# ============================================================
# 手动添加端口跳跃
# ============================================================
add_hop_interactive() {
    detect_ssh
    hr; echo -e "${C}手动添加端口跳跃规则${W}"; hr
    read -rp "$(echo -e "${Y}端口范围（如 20000-50000）: ${W}")" hop_range
    read -rp "$(echo -e "${Y}目标端口（代理实际监听端口）: ${W}")" target_port
    [[ "$hop_range"   =~ ^[0-9]+-[0-9]+$ ]] || err "范围格式错误，示例: 20000-50000"
    [[ "$target_port" =~ ^[0-9]+$         ]] || err "目标端口格式错误"
    local s e
    s=$(echo "$hop_range" | cut -d- -f1)
    e=$(echo "$hop_range" | cut -d- -f2)
    [[ "$s" -ge "$e" ]] && err "起始端口须小于结束端口"
    HOP_RULES+=("${s}-${e}->${target_port}")

    # 保留现有已开放端口
    while read -r p; do add_port "$p"; done < <(
        nft list chain inet "$NFT_TABLE" input_chain 2>/dev/null \
            | grep -oE 'dport \{[^}]+\}' | grep -oE '[0-9]+' || true)
    add_port 80; add_port 443

    apply_rules
    save_rules
    ok "端口跳跃 ${hop_range} → ${target_port} 添加完成"
}

# ============================================================
# 显示状态
# ============================================================
show_status() {
    hr; echo -e "${C}防火墙当前状态${W}"; hr

    echo -e "${G}▸ nftables 规则:${W}"
    nft list ruleset 2>/dev/null || warn "nftables 规则为空"

    echo -e "\n${G}▸ 公网监听端口 (ss):${W}"
    get_public_ports | while read -r p; do
        local proc
        proc=$(ss -tulnp 2>/dev/null | grep ":${p}[^0-9]" \
            | grep -oE '"[^"]+"' | head -1 | tr -d '"' || true)
        printf "  • %-6s %s\n" "$p" "${proc:-(未知)}"
    done

    echo -e "\n${G}▸ 关键 sysctl:${W}"
    for param in net.ipv4.ip_forward net.ipv4.conf.all.rp_filter net.ipv4.tcp_timestamps; do
        printf "  • %-45s = %s\n" "$param" "$(sysctl -n "$param" 2>/dev/null || echo 未知)"
    done

    echo -e "\n${G}▸ nftables 服务:${W}"
    systemctl is-active --quiet nftables && ok "nftables.service 运行中" || warn "nftables.service 未运行"
    hr
}

# ============================================================
# 重置
# ============================================================
do_reset() {
    echo -e "${R}⚠ 清除所有规则并全部放行，确认？[y/N]${W}"
    read -r ans
    [[ "${ans,,}" == y ]] || { info "已取消"; exit 0; }
    nft flush ruleset 2>/dev/null || true
    > "$NFT_CONF"
    systemctl stop nftables &>/dev/null || true
    ok "防火墙已重置，所有流量放行"
}

# ============================================================
# 摘要
# ============================================================
show_summary() {
    hr; echo -e "${G}🎉 防火墙配置完成！${W}"; hr
    echo -e "${C}SSH 端口 :${W} $SSH_PORT  ${Y}（防暴力破解已启用）${W}"
    echo -e "${C}开放端口 :${W} ${OPEN_PORTS[*]:-无}"
    if [[ ${#HOP_RULES[@]} -gt 0 ]]; then
        echo -e "${C}端口跳跃 :${W}"
        for rule in "${HOP_RULES[@]}"; do
            parse_hop "$rule"
            echo -e "  ${G}•${W} ${HOP_S}-${HOP_E} → ${HOP_T}"
        done
    else
        warn "未配置端口跳跃  →  如需添加: bash nftables_fw.sh --add-hop"
    fi
    hr
    echo -e "${Y}常用命令:${W}"
    echo "  查看状态   : bash nftables_fw.sh --status"
    echo "  添加跳跃   : bash nftables_fw.sh --add-hop"
    echo "  重置防火墙 : bash nftables_fw.sh --reset"
    echo "  查看规则   : nft list ruleset"
    hr
}

# ============================================================
# 主流程
# ============================================================
main() {
    trap 'echo -e "\n${R}已中断${W}"; exit 130' INT TERM
    hr; echo -e "${G}   nftables 防火墙管理脚本 v${VERSION}${W}"; hr

    [[ $_status -eq 1 ]] && { show_status;         exit 0; }
    [[ $_reset  -eq 1 ]] && { do_reset;             exit 0; }
    [[ $_addhop -eq 1 ]] && { add_hop_interactive;  exit 0; }

    install_deps
    detect_ssh

    # 先检测跳跃规则（端口过滤时排除跳跃范围）
    detect_existing_hop_rules
    detect_hysteria_hop

    detect_ports
    add_port 80; add_port 443

    mapfile -t OPEN_PORTS < <(printf '%s\n' "${OPEN_PORTS[@]:-}" | sort -un) || true

    echo
    info "SSH 端口 : $SSH_PORT"
    info "开放端口 : ${OPEN_PORTS[*]:-无}"
    for rule in "${HOP_RULES[@]:-}"; do
        [[ -z "$rule" ]] && continue
        parse_hop "$rule"; info "端口跳跃 : ${HOP_S}-${HOP_E} → ${HOP_T}"
    done
    [[ ${#HOP_RULES[@]} -eq 0 ]] && warn "未检测到端口跳跃  →  如需添加: bash nftables_fw.sh --add-hop"
    echo

    read -rp "$(echo -e "${Y}确认应用以上配置？[y/N]: ${W}")" ans
    [[ "${ans,,}" == y ]] || { info "已取消"; exit 0; }

    apply_rules
    save_rules
    show_summary
}

main "$@"

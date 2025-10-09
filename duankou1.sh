#!/bin/bash
# 精确代理端口防火墙管理脚本（nftables 优化版）
# 版本: 2.2.1

set +e

# 颜色定义
readonly GREEN='\033[32m'
readonly YELLOW='\033[33m'
readonly RED='\033[31m'
readonly BLUE='\033[34m'
readonly CYAN='\033[36m'
readonly RESET='\033[0m'

# 脚本信息
readonly SCRIPT_VERSION="2.2.1"
readonly SCRIPT_NAME="精确代理端口防火墙管理脚本"

echo -e "${YELLOW}== 🚀 ${SCRIPT_NAME} v${SCRIPT_VERSION} ==${RESET}"
echo -e "${CYAN}针对 Hiddify、3X-UI、X-UI、Sing-box、Xray 等代理面板优化${RESET}"

# 权限检查
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}❌ 需要 root 权限运行此脚本${RESET}"
    exit 1
fi

# 全局变量
DEBUG_MODE=false
DRY_RUN=false
AUTO_MODE=false
SSH_PORT=""
DETECTED_PORTS=()
NAT_RULES=()
OPENED_PORTS=0

# nftables 配置
readonly NFT_TABLE="proxy_firewall"
readonly NFT_CHAIN_INPUT="input_chain"
readonly NFT_CHAIN_FORWARD="forward_chain"
readonly NFT_CHAIN_OUTPUT="output_chain"
readonly NFT_CHAIN_PREROUTING="prerouting_chain"
readonly NFT_CHAIN_SSH="ssh_protection"

# 默认永久开放端口
DEFAULT_OPEN_PORTS=(80 443)

# 代理核心进程
PROXY_CORE_PROCESSES=(
    "xray" "v2ray" "sing-box" "singbox"
    "hysteria" "tuic" "juicity"
    "hiddify" "x-ui" "3x-ui"
    "trojan" "shadowsocks" "ss-server"
    "brook" "gost" "naive" "clash"
)

# 内部服务端口
INTERNAL_SERVICE_PORTS=(
    8181 10085 10086 9090 3000 8000
    54321 62789
)

# 危险端口黑名单
BLACKLIST_PORTS=(
    22 23 25 53 111 135 139 445
    1433 1521 3306 5432 6379 27017
    3389 5900
)

# 辅助函数
debug_log() { 
    if [ "$DEBUG_MODE" = true ]; then
        echo -e "${BLUE}[调试] $1${RESET}"
    fi
}

error_exit() { 
    echo -e "${RED}❌ $1${RESET}"
    exit 1
}

warning() { 
    echo -e "${YELLOW}⚠️  $1${RESET}"
}

success() { 
    echo -e "${GREEN}✅ $1${RESET}"
}

info() { 
    echo -e "${CYAN}ℹ️  $1${RESET}"
}

# 显示帮助信息
show_help() {
    cat << 'EOF'
精确代理端口防火墙管理脚本 v2.2.1

用法: bash script.sh [选项]

选项:
    --auto            自动模式，无需人工确认
    --debug           显示详细调试信息
    --dry-run         预览模式，不实际修改防火墙
    --add-range       交互式端口范围添加
    --reset           重置防火墙到默认状态
    --clean-nat       清理所有NAT规则
    --status          显示当前防火墙状态
    --help, -h        显示此帮助信息

支持的代理软件:
    ✓ Hiddify / 3X-UI / X-UI
    ✓ Xray / V2Ray / Sing-box
    ✓ Hysteria / Trojan / Shadowsocks

安全功能:
    ✓ 精确端口识别
    ✓ 自动过滤内部服务端口
    ✓ SSH 暴力破解防护
    ✓ NAT 端口转发支持

EOF
}

# 超时读取函数
read_with_timeout() {
    local prompt="$1"
    local timeout="${2:-10}"
    local default="${3:-N}"
    
    echo -e "$prompt"
    
    if [ "$AUTO_MODE" = true ]; then
        echo -e "${CYAN}[自动模式] 使用默认值: $default${RESET}"
        REPLY="$default"
        return 0
    fi
    
    if read -t "$timeout" -r; then
        return 0
    else
        echo -e "\n${YELLOW}超时，使用默认值: $default${RESET}"
        REPLY="$default"
        return 1
    fi
}

# 解析参数
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --auto) AUTO_MODE=true; shift ;;
            --debug) DEBUG_MODE=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --add-range) add_port_range_interactive; exit 0 ;;
            --reset) reset_firewall; exit 0 ;;
            --clean-nat) clean_nat_rules_only; exit 0 ;;
            --status) show_firewall_status; exit 0 ;;
            --help|-h) show_help; exit 0 ;;
            *) error_exit "未知参数: $1" ;;
        esac
    done
}

# 检查系统环境
check_system() {
    info "检查系统环境..."
    
    if ! command -v nft >/dev/null 2>&1; then
        info "安装 nftables..."
        if [ "$DRY_RUN" = false ]; then
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq && apt-get install -y nftables >/dev/null 2>&1
            elif command -v yum >/dev/null 2>&1; then
                yum install -y nftables >/dev/null 2>&1
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y nftables >/dev/null 2>&1
            else
                error_exit "无法自动安装 nftables"
            fi
        fi
    fi
    
    if ! command -v ss >/dev/null 2>&1; then
        info "安装 iproute2..."
        if [ "$DRY_RUN" = false ]; then
            if command -v apt-get >/dev/null 2>&1; then
                apt-get install -y iproute2 >/dev/null 2>&1
            elif command -v yum >/dev/null 2>&1; then
                yum install -y iproute >/dev/null 2>&1
            fi
        fi
    fi
    
    if [ "$DRY_RUN" = false ]; then
        modprobe nf_tables 2>/dev/null || true
    fi
    
    success "系统环境检查完成"
    return 0
}

# 检测 SSH 端口
detect_ssh_port() {
    debug_log "检测 SSH 端口..."
    
    local ssh_port=""
    
    if command -v ss >/dev/null 2>&1; then
        ssh_port=$(ss -tlnp 2>/dev/null | grep -i 'sshd' | head -1 | awk '{print $4}' | grep -oE '[0-9]+$' || echo "")
    fi
    
    if [ -z "$ssh_port" ] && [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -E '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 || echo "")
    fi
    
    if [ -z "$ssh_port" ]; then
        ssh_port="22"
    fi
    
    SSH_PORT="$ssh_port"
    info "SSH 端口: $SSH_PORT"
    return 0
}

# 检测现有的 NAT 规则
detect_existing_nat_rules() {
    info "检测现有端口转发规则..."
    
    local nat_rules=()
    
    # 检查 nftables NAT 规则
    if command -v nft >/dev/null 2>&1; then
        local tables_output=$(nft list tables 2>/dev/null || echo "")
        
        if [ -n "$tables_output" ]; then
            while read -r line; do
                local family=$(echo "$line" | awk '{print $1}')
                local table=$(echo "$line" | awk '{print $2}')
                
                if [ -n "$table" ]; then
                    local nat_output=$(nft list table "$family" "$table" 2>/dev/null | grep "dnat to" || echo "")
                    
                    if [ -n "$nat_output" ]; then
                        while IFS= read -r rule_line; do
                            if echo "$rule_line" | grep -qE 'dport[[:space:]]+[0-9]+-[0-9]+.*dnat[[:space:]]+to[[:space:]]+:[0-9]+'; then
                                local range=$(echo "$rule_line" | grep -oE 'dport[[:space:]]+[0-9]+-[0-9]+' | awk '{print $2}')
                                local target=$(echo "$rule_line" | grep -oE 'dnat[[:space:]]+to[[:space:]]+:[0-9]+' | grep -oE '[0-9]+

# 清理NAT规则
clean_nat_rules_only() {
    echo -e "${YELLOW}🔄 清理NAT规则${RESET}"
    
    if [ "$DRY_RUN" = false ] && [ "$AUTO_MODE" = false ]; then
        read_with_timeout "${YELLOW}确认清理所有NAT规则？[y/N]${RESET}" 10 "N"
        if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
            info "清理操作已取消"
            return 0
        fi
    fi
    
    if [ "$DRY_RUN" = false ]; then
        if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
            nft flush chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null || true
            success "NAT规则已清理"
            save_nftables_rules
        else
            info "未找到NAT规则表"
        fi
    else
        info "[预览模式] 将清理所有NAT规则"
    fi
    
    return 0
}

# 交互式端口范围添加
add_port_range_interactive() {
    echo -e "${CYAN}🔧 配置端口转发规则${RESET}"
    echo -e "${YELLOW}示例: 16820-16888 转发到 16801${RESET}"
    
    while true; do
        echo -e "\n${CYAN}输入端口范围 (格式: 起始-结束):${RESET}"
        read -r port_range
        
        if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start="${BASH_REMATCH[1]}"
            local end="${BASH_REMATCH[2]}"
            
            if [ "$start" -ge "$end" ]; then
                warning "起始端口必须小于结束端口"
                continue
            fi
            
            echo -e "${CYAN}输入目标端口:${RESET}"
            read -r target
            
            if [[ "$target" =~ ^[0-9]+$ ]] && [ "$target" -ge 1 ] && [ "$target" -le 65535 ]; then
                NAT_RULES+=("$start-$end->$target")
                DETECTED_PORTS+=("$target")
                success "添加: $start-$end -> $target"
                
                read_with_timeout "${YELLOW}继续添加？[y/N]${RESET}" 10 "N"
                [[ ! "$REPLY" =~ ^[Yy]$ ]] && break
            else
                warning "无效的目标端口"
            fi
        else
            warning "无效的端口范围格式"
        fi
    done
    
    return 0
}

# 检测代理进程
detect_proxy_processes() {
    info "检测代理服务进程..."
    
    local found=()
    for process in "${PROXY_CORE_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found+=("$process")
            debug_log "发现进程: $process"
        fi
    done
    
    if [ ${#found[@]} -gt 0 ]; then
        local found_list="${found[*]}"
        success "检测到代理进程: $found_list"
        return 0
    else
        warning "未检测到运行中的代理进程"
        return 1
    fi
}

# 从配置文件解析端口
parse_config_ports() {
    info "从配置文件解析端口..."
    
    local config_files=(
        "/etc/xray/config.json"
        "/usr/local/etc/xray/config.json"
        "/etc/v2ray/config.json"
        "/etc/sing-box/config.json"
        "/opt/sing-box/config.json"
        "/etc/x-ui/config.json"
        "/opt/3x-ui/bin/config.json"
    )
    
    local ports=()
    local port_hopping_detected=false
    
    for file in "${config_files[@]}"; do
        if [ ! -f "$file" ]; then
            continue
        fi
        
        debug_log "分析配置文件: $file"
        
        if [[ "$file" =~ \.json$ ]]; then
            # 提取普通端口
            local found=$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' "$file" 2>/dev/null | grep -oE '[0-9]+' | sort -nu || echo "")
            if [ -n "$found" ]; then
                while read -r port; do
                    if [ -n "$port" ]; then
                        ports+=("$port")
                    fi
                done <<< "$found"
            fi
            
            # 检测端口跳跃配置（port hopping / port range）
            # 格式1: "portRange": "16820-16888"
            local port_range=$(grep -oE '"portRange"[[:space:]]*:[[:space:]]*"[0-9]+-[0-9]+"' "$file" 2>/dev/null | grep -oE '[0-9]+-[0-9]+' || echo "")
            
            # 格式2: "ports": "16820-16888"
            if [ -z "$port_range" ]; then
                port_range=$(grep -oE '"ports"[[:space:]]*:[[:space:]]*"[0-9]+-[0-9]+"' "$file" 2>/dev/null | grep -oE '[0-9]+-[0-9]+' || echo "")
            fi
            
            # 格式3: "port_range": "16820-16888"
            if [ -z "$port_range" ]; then
                port_range=$(grep -oE '"port_range"[[:space:]]*:[[:space:]]*"[0-9]+-[0-9]+"' "$file" 2>/dev/null | grep -oE '[0-9]+-[0-9]+' || echo "")
            fi
            
            # 格式4: "listen_port": xxxx 和 "port_hopping": ["start-end"]
            if [ -z "$port_range" ]; then
                port_range=$(grep -oE '"port_hopping"[[:space:]]*:[[:space:]]*\[[[:space:]]*"[0-9]+-[0-9]+"' "$file" 2>/dev/null | grep -oE '[0-9]+-[0-9]+' || echo "")
            fi
            
            if [ -n "$port_range" ]; then
                port_hopping_detected=true
                
                # 提取实际监听端口作为目标端口
                local listen_port=$(grep -oE '"(listen_port|port)"[[:space:]]*:[[:space:]]*[0-9]+' "$file" 2>/dev/null | grep -oE '[0-9]+' | head -1 || echo "")
                
                if [ -n "$listen_port" ]; then
                    info "检测到端口跳跃配置: $port_range -> $listen_port"
                    NAT_RULES+=("$port_range->$listen_port")
                    DETECTED_PORTS+=("$listen_port")
                else
                    warning "检测到端口范围 $port_range 但无法确定目标端口"
                    echo -e "${YELLOW}稍后需要手动配置目标端口${RESET}"
                fi
            fi
        fi
    done
    
    if [ ${#ports[@]} -gt 0 ]; then
        local unique=($(printf '%s\n' "${ports[@]}" | sort -nu))
        for port in "${unique[@]}"; do
            if ! is_internal_service_port "$port" && [ -n "$port" ]; then
                DETECTED_PORTS+=("$port")
            fi
        done
        success "从配置文件解析到 ${#unique[@]} 个端口"
    fi
    
    if [ "$port_hopping_detected" = true ]; then
        echo -e "\n${CYAN}🎯 检测到端口跳跃配置${RESET}"
        echo -e "${YELLOW}将自动配置 NAT 端口转发规则${RESET}"
    fi
    
    return 0
}

# 检测监听端口
detect_listening_ports() {
    info "检测当前监听端口..."
    
    if ! command -v ss >/dev/null 2>&1; then
        warning "ss 命令不可用"
        return 0
    fi
    
    local ports=()
    local ss_output=$(ss -tulnp 2>/dev/null || echo "")
    
    if [ -z "$ss_output" ]; then
        warning "无法获取监听端口信息"
        return 0
    fi
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^(Netid|State) ]]; then
            continue
        fi
        
        if ! echo "$line" | grep -qE '(LISTEN|UNCONN)'; then
            continue
        fi
        
        local port=$(echo "$line" | awk '{print $5}' | grep -oE '[0-9]+$' || echo "")
        local process_match=$(echo "$line" | grep -oE 'users:\(\("([^"]+)"' || echo "")
        local process=$(echo "$process_match" | grep -oE '"[^"]+"' | tr -d '"' | head -1 || echo "")
        
        if [ -z "$port" ] || [ "$port" = "$SSH_PORT" ]; then
            continue
        fi
        
        local is_proxy=false
        if [ -n "$process" ]; then
            for proxy in "${PROXY_CORE_PROCESSES[@]}"; do
                if echo "$process" | grep -q "$proxy"; then
                    is_proxy=true
                    break
                fi
            done
        fi
        
        if [ "$is_proxy" = true ] && ! is_internal_service_port "$port"; then
            local addr=$(echo "$line" | awk '{print $5}')
            if ! echo "$addr" | grep -qE '^(127\.|::1|\[::1\])'; then
                ports+=("$port")
                debug_log "检测到端口: $port 进程: $process"
            fi
        fi
    done <<< "$ss_output"
    
    if [ ${#ports[@]} -gt 0 ]; then
        local unique=($(printf '%s\n' "${ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique[@]}")
        success "检测到 ${#unique[@]} 个监听端口"
    fi
    
    return 0
}

# 检查端口是否为内部服务
is_internal_service_port() {
    local port="$1"
    for internal in "${INTERNAL_SERVICE_PORTS[@]}"; do
        if [ "$port" = "$internal" ]; then
            return 0
        fi
    done
    return 1
}

# 端口安全检查
is_port_safe() {
    local port="$1"
    
    for blacklist in "${BLACKLIST_PORTS[@]}"; do
        if [ "$port" = "$blacklist" ]; then
            return 1
        fi
    done
    
    if is_internal_service_port "$port"; then
        return 1
    fi
    
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    
    return 0
}

# 过滤并确认端口
filter_and_confirm_ports() {
    info "智能端口分析..."
    
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    
    local all=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    local safe=()
    local unsafe=()
    
    for port in "${all[@]}"; do
        if is_port_safe "$port"; then
            safe+=("$port")
        else
            unsafe+=("$port")
        fi
    done
    
    if [ ${#safe[@]} -gt 0 ]; then
        echo -e "\n${GREEN}✅ 将开放的端口:${RESET}"
        for port in "${safe[@]}"; do
            local is_default=false
            for def_port in "${DEFAULT_OPEN_PORTS[@]}"; do
                if [ "$port" = "$def_port" ]; then
                    is_default=true
                    break
                fi
            done
            
            if [ "$is_default" = true ]; then
                echo -e "  ${GREEN}✓ $port - 默认${RESET}"
            else
                echo -e "  ${GREEN}✓ $port${RESET}"
            fi
        done
    fi
    
    if [ ${#unsafe[@]} -gt 0 ]; then
        echo -e "\n${RED}❌ 已跳过的危险端口:${RESET}"
        for port in "${unsafe[@]}"; do
            echo -e "  ${RED}✗ $port${RESET}"
        done
    fi
    
    if [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -eq 0 ] && [ "$AUTO_MODE" = false ]; then
        read_with_timeout "\n${CYAN}配置端口转发功能吗？[y/N]${RESET}" 10 "N"
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            add_port_range_interactive
        fi
    fi
    
    if [ "$DRY_RUN" = false ] && [ "$AUTO_MODE" = false ]; then
        echo -e "\n${CYAN}📋 摘要:${RESET}"
        echo -e "  • 开放端口: ${#safe[@]} 个"
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "  • 端口转发: ${#NAT_RULES[@]} 条"
        fi
        
        read_with_timeout "\n${YELLOW}确认应用配置？[Y/n]${RESET}" 10 "Y"
        if [[ "$REPLY" =~ ^[Nn]$ ]]; then
            info "用户取消操作"
            exit 0
        fi
    fi
    
    DETECTED_PORTS=($(printf '%s\n' "${safe[@]}" | sort -nu))
    if [ ${#DETECTED_PORTS[@]} -eq 0 ]; then
        DETECTED_PORTS=("${DEFAULT_OPEN_PORTS[@]}")
    fi
    
    return 0
}

# 清理现有防火墙
cleanup_firewalls() {
    info "清理现有防火墙配置..."
    
    if [ "$DRY_RUN" = true ]; then
        return 0
    fi
    
    for service in ufw firewalld; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
        fi
    done
    
    nft flush ruleset 2>/dev/null || true
    
    if command -v iptables >/dev/null 2>&1; then
        iptables -P INPUT ACCEPT 2>/dev/null || true
        iptables -P FORWARD ACCEPT 2>/dev/null || true
        iptables -P OUTPUT ACCEPT 2>/dev/null || true
        iptables -F 2>/dev/null || true
        iptables -X 2>/dev/null || true
        iptables -t nat -F 2>/dev/null || true
        iptables -t nat -X 2>/dev/null || true
    fi
    
    success "防火墙清理完成"
    return 0
}

# 创建 nftables 基础结构
create_nftables_base() {
    if [ "$DRY_RUN" = true ]; then
        return 0
    fi
    
    info "创建 nftables 规则..."
    
    nft add table inet "$NFT_TABLE"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" "{ type filter hook input priority 0 ; policy drop ; }"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_FORWARD" "{ type filter hook forward priority 0 ; policy drop ; }"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_OUTPUT" "{ type filter hook output priority 0 ; policy accept ; }"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" "{ type nat hook prerouting priority -100 ; }"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_SSH"
    
    return 0
}

# 应用防火墙规则
apply_firewall_rules() {
    info "应用防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 规则预览已完成"
        return 0
    fi
    
    create_nftables_base
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" iif "lo" accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" ct state established,related accept
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" icmp type echo-request limit rate 10/second accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" icmpv6 type echo-request limit rate 10/second accept
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" ct state established,related accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" tcp dport "$SSH_PORT" limit rate 4/minute burst 4 packets accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" tcp dport "$SSH_PORT" drop
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport "$SSH_PORT" jump "$NFT_CHAIN_SSH"
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        local ports=$(printf '%s,' "${DETECTED_PORTS[@]}")
        ports="${ports%,}"
        nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport "{ $ports }" accept
        nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" udp dport "{ $ports }" accept
        success "已开放 ${#DETECTED_PORTS[@]} 个端口"
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        for rule in "${NAT_RULES[@]}"; do
            local range="${rule%->*}"
            local target="${rule##*->}"
            
            nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" tcp dport "$range" dnat to ":$target"
            nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" udp dport "$range" dnat to ":$target"
            nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport "$range" accept
            nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" udp dport "$range" accept
            
            success "端口转发: $range -> $target"
        done
    fi
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" limit rate 3/minute burst 3 packets log prefix '"fw-drop: "' level warn
    
    OPENED_PORTS=${#DETECTED_PORTS[@]}
    save_nftables_rules
    success "防火墙规则应用完成"
    return 0
}

# 保存规则
save_nftables_rules() {
    if [ "$DRY_RUN" = true ]; then
        return 0
    fi
    
    mkdir -p /etc/nftables.d
    nft list ruleset > /etc/nftables.conf
    
    cat > /etc/systemd/system/nftables-restore.service << 'EOF'
[Unit]
Description=Restore nftables rules
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/nftables.conf
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable nftables-restore.service >/dev/null 2>&1 || true
    
    success "规则已保存并配置开机自启"
    return 0
}

# 重置防火墙
reset_firewall() {
    echo -e "${YELLOW}🔄 重置防火墙${RESET}"
    
    if [ "$DRY_RUN" = false ] && [ "$AUTO_MODE" = false ]; then
        read_with_timeout "${RED}确认重置所有防火墙规则？[y/N]${RESET}" 10 "N"
        if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    if [ "$DRY_RUN" = false ]; then
        nft flush ruleset 2>/dev/null || true
        echo "" > /etc/nftables.conf 2>/dev/null || true
        systemctl disable nftables-restore.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/nftables-restore.service
        systemctl daemon-reload
        success "防火墙已重置"
    else
        info "[预览模式] 将重置防火墙"
    fi
    
    return 0
}

# 显示防火墙状态
show_firewall_status() {
    echo -e "${CYAN}🔍 防火墙状态${RESET}\n"
    
    if ! nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        warning "未找到防火墙规则表"
        return 1
    fi
    
    echo -e "${GREEN}📊 规则统计:${RESET}"
    local input_rules=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" 2>/dev/null | grep -c "accept\|drop" || echo "0")
    local nat_rules=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep -c "dnat to" || echo "0")
    echo -e "  INPUT 规则: $input_rules"
    echo -e "  NAT 规则: $nat_rules"
    
    echo -e "\n${GREEN}🔓 开放端口:${RESET}"
    local port_rules=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" 2>/dev/null | grep -E "(tcp|udp) dport" | grep "accept" || echo "")
    if [ -n "$port_rules" ]; then
        while read -r line; do
            local ports=$(echo "$line" | grep -oE 'dport \{[^}]+\}' | sed 's/dport //g' | tr -d '{}')
            if [ -z "$ports" ]; then
                ports=$(echo "$line" | grep -oE 'dport [0-9-]+' | sed 's/dport //g')
            fi
            local proto=$(echo "$line" | grep -oE "tcp|udp")
            if [ -n "$ports" ]; then
                echo -e "  • $ports - $proto"
            fi
        done <<< "$port_rules"
    else
        echo -e "  ${YELLOW}无开放端口${RESET}"
    fi
    
    echo -e "\n${GREEN}🔄 端口转发:${RESET}"
    local nat_output=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep "dnat to" || echo "")
    if [ -n "$nat_output" ]; then
        while read -r line; do
            local range=$(echo "$line" | grep -oE 'dport [0-9-]+' | sed 's/dport //g')
            local target=$(echo "$line" | grep -oE 'dnat to :[0-9]+' | sed 's/dnat to ://g')
            if [ -n "$range" ] && [ -n "$target" ]; then
                echo -e "  • $range → $target"
            fi
        done <<< "$nat_output"
    else
        echo -e "  ${YELLOW}无端口转发规则${RESET}"
    fi
    
    echo -e "\n${GREEN}🛡️  SSH 保护:${RESET}"
    if nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_SSH" 2>/dev/null | grep -q "limit rate"; then
        echo -e "  ${GREEN}✓ 已启用${RESET}"
    else
        echo -e "  ${YELLOW}⚠️  未启用${RESET}"
    fi
    
    return 0
}

# 显示最终状态
show_final_status() {
    echo -e "\n${GREEN}=================================="
    echo -e "🎉 防火墙配置完成！"
    echo -e "==================================${RESET}"
    
    echo -e "\n${CYAN}📊 配置摘要:${RESET}"
    echo -e "  ${GREEN}✓ 开放端口: $OPENED_PORTS 个${RESET}"
    echo -e "  ${GREEN}✓ SSH 端口: $SSH_PORT - 已保护${RESET}"
    echo -e "  ${GREEN}✓ 防火墙: nftables${RESET}"
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "  ${GREEN}✓ 端口转发: ${#NAT_RULES[@]} 条${RESET}"
    fi
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 开放端口列表:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            local is_default=false
            for def_port in "${DEFAULT_OPEN_PORTS[@]}"; do
                if [ "$port" = "$def_port" ]; then
                    is_default=true
                    break
                fi
            done
            
            if [ "$is_default" = true ]; then
                echo -e "  ${GREEN}• $port - TCP/UDP - 默认${RESET}"
            else
                echo -e "  ${GREEN}• $port - TCP/UDP${RESET}"
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${CYAN}🔄 端口转发规则:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            local range="${rule%->*}"
            local target="${rule##*->}"
            echo -e "  ${CYAN}• 端口范围 $range → 目标端口 $target${RESET}"
            
            # 检查目标端口是否在监听
            if [ "$DRY_RUN" = false ]; then
                if ss -tlnp 2>/dev/null | grep -q ":$target "; then
                    echo -e "    ${GREEN}✓ 目标端口 $target 正在监听${RESET}"
                else
                    echo -e "    ${YELLOW}⚠️  目标端口 $target 未监听，请确保代理服务已启动${RESET}"
                fi
            fi
        done
        
        echo -e "\n${CYAN}💡 端口跳跃说明:${RESET}"
        echo -e "  ${YELLOW}• 客户端可以连接到范围内的任意端口${RESET}"
        echo -e "  ${YELLOW}• 所有连接都会转发到目标端口${RESET}"
        echo -e "  ${YELLOW}• 增强了抗封锁能力${RESET}"
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}🔍 预览模式，未实际修改${RESET}"
        return 0
    fi
    
    echo -e "\n${CYAN}🔧 常用命令:${RESET}"
    echo -e "  ${YELLOW}查看规则:${RESET} nft list ruleset"
    echo -e "  ${YELLOW}查看状态:${RESET} bash $0 --status"
    echo -e "  ${YELLOW}添加转发:${RESET} bash $0 --add-range"
    echo -e "  ${YELLOW}清理NAT:${RESET} bash $0 --clean-nat"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash $0 --reset"
    
    echo -e "\n${GREEN}✅ 配置完成，服务器安全已启用！${RESET}"
    
    return 0
}

# 主函数
main() {
    set +e
    trap 'echo -e "\n${RED}操作被中断${RESET}"; exit 130' INT TERM
    
    parse_arguments "$@"
    
    echo -e "\n${CYAN}🚀 开始配置...${RESET}"
    
    if ! check_system; then
        error_exit "系统环境检查失败"
    fi
    
    if ! detect_ssh_port; then
        error_exit "SSH 端口检测失败"
    fi
    
    if ! detect_existing_nat_rules; then
        warning "NAT 规则检测失败，继续..."
    fi
    
    if ! cleanup_firewalls; then
        error_exit "防火墙清理失败"
    fi
    
    if ! detect_proxy_processes; then
        warning "未检测到代理进程，将使用默认配置"
    fi
    
    if ! parse_config_ports; then
        warning "配置文件解析失败，继续..."
    fi
    
    if ! detect_listening_ports; then
        warning "监听端口检测失败，继续..."
    fi
    
    if ! filter_and_confirm_ports; then
        error_exit "端口过滤失败"
    fi
    
    if ! apply_firewall_rules; then
        error_exit "防火墙规则应用失败"
    fi
    
    show_final_status
}

# 执行主函数
main "$@")
                                
                                if [ -n "$range" ] && [ -n "$target" ]; then
                                    nat_rules+=("$range->$target")
                                    debug_log "发现 NAT 规则: $range -> $target"
                                fi
                            fi
                        done <<< "$nat_output"
                    fi
                fi
            done <<< "$tables_output"
        fi
    fi
    
    # 也检查 iptables NAT 规则（兼容性）
    if command -v iptables >/dev/null 2>&1; then
        local ipt_nat=$(iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null | grep "DNAT" || echo "")
        
        if [ -n "$ipt_nat" ]; then
            while IFS= read -r line; do
                if echo "$line" | grep -qE "dpts:[0-9]+:[0-9]+"; then
                    local range=$(echo "$line" | grep -oE "dpts:[0-9]+:[0-9]+" | sed 's/dpts://' | sed 's/:/-/')
                    local target=$(echo "$line" | grep -oE "to:[0-9\.]*:[0-9]+" | grep -oE "[0-9]+$")
                    
                    if [ -n "$range" ] && [ -n "$target" ]; then
                        nat_rules+=("$range->$target")
                        debug_log "发现 iptables NAT 规则: $range -> $target"
                    fi
                fi
            done <<< "$ipt_nat"
        fi
    fi
    
    if [ ${#nat_rules[@]} -gt 0 ]; then
        NAT_RULES=($(printf '%s\n' "${nat_rules[@]}" | sort -u))
        echo -e "\n${GREEN}🔄 现有端口转发规则:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            echo -e "  ${GREEN}• $rule${RESET}"
        done
        
        # 将目标端口添加到检测端口列表
        for rule in "${NAT_RULES[@]}"; do
            local target="${rule##*->}"
            if [ -n "$target" ]; then
                DETECTED_PORTS+=("$target")
                debug_log "添加NAT目标端口到开放列表: $target"
            fi
        done
        
        success "检测到 ${#NAT_RULES[@]} 条端口转发规则"
    else
        info "未检测到现有端口转发规则"
    fi
    
    return 0
}

# 清理NAT规则
clean_nat_rules_only() {
    echo -e "${YELLOW}🔄 清理NAT规则${RESET}"
    
    if [ "$DRY_RUN" = false ] && [ "$AUTO_MODE" = false ]; then
        read_with_timeout "${YELLOW}确认清理所有NAT规则？[y/N]${RESET}" 10 "N"
        if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
            info "清理操作已取消"
            return 0
        fi
    fi
    
    if [ "$DRY_RUN" = false ]; then
        if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
            nft flush chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null || true
            success "NAT规则已清理"
            save_nftables_rules
        else
            info "未找到NAT规则表"
        fi
    else
        info "[预览模式] 将清理所有NAT规则"
    fi
    
    return 0
}

# 交互式端口范围添加
add_port_range_interactive() {
    echo -e "${CYAN}🔧 配置端口转发规则${RESET}"
    echo -e "${YELLOW}示例: 16820-16888 转发到 16801${RESET}"
    
    while true; do
        echo -e "\n${CYAN}输入端口范围 (格式: 起始-结束):${RESET}"
        read -r port_range
        
        if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start="${BASH_REMATCH[1]}"
            local end="${BASH_REMATCH[2]}"
            
            if [ "$start" -ge "$end" ]; then
                warning "起始端口必须小于结束端口"
                continue
            fi
            
            echo -e "${CYAN}输入目标端口:${RESET}"
            read -r target
            
            if [[ "$target" =~ ^[0-9]+$ ]] && [ "$target" -ge 1 ] && [ "$target" -le 65535 ]; then
                NAT_RULES+=("$start-$end->$target")
                DETECTED_PORTS+=("$target")
                success "添加: $start-$end -> $target"
                
                read_with_timeout "${YELLOW}继续添加？[y/N]${RESET}" 10 "N"
                [[ ! "$REPLY" =~ ^[Yy]$ ]] && break
            else
                warning "无效的目标端口"
            fi
        else
            warning "无效的端口范围格式"
        fi
    done
    
    return 0
}

# 检测代理进程
detect_proxy_processes() {
    info "检测代理服务进程..."
    
    local found=()
    for process in "${PROXY_CORE_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found+=("$process")
            debug_log "发现进程: $process"
        fi
    done
    
    if [ ${#found[@]} -gt 0 ]; then
        local found_list="${found[*]}"
        success "检测到代理进程: $found_list"
        return 0
    else
        warning "未检测到运行中的代理进程"
        return 1
    fi
}

# 从配置文件解析端口
parse_config_ports() {
    info "从配置文件解析端口..."
    
    local config_files=(
        "/etc/xray/config.json"
        "/usr/local/etc/xray/config.json"
        "/etc/v2ray/config.json"
        "/etc/sing-box/config.json"
        "/opt/sing-box/config.json"
        "/etc/x-ui/config.json"
        "/opt/3x-ui/bin/config.json"
    )
    
    local ports=()
    for file in "${config_files[@]}"; do
        if [ ! -f "$file" ]; then
            continue
        fi
        
        debug_log "分析: $file"
        
        if [[ "$file" =~ \.json$ ]]; then
            local found=$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' "$file" 2>/dev/null | grep -oE '[0-9]+' | sort -nu || echo "")
            if [ -n "$found" ]; then
                while read -r port; do
                    if [ -n "$port" ]; then
                        ports+=("$port")
                    fi
                done <<< "$found"
            fi
        fi
    done
    
    if [ ${#ports[@]} -gt 0 ]; then
        local unique=($(printf '%s\n' "${ports[@]}" | sort -nu))
        for port in "${unique[@]}"; do
            if ! is_internal_service_port "$port" && [ -n "$port" ]; then
                DETECTED_PORTS+=("$port")
            fi
        done
        success "从配置文件解析到 ${#unique[@]} 个端口"
    fi
    
    return 0
}

# 检测监听端口
detect_listening_ports() {
    info "检测当前监听端口..."
    
    if ! command -v ss >/dev/null 2>&1; then
        warning "ss 命令不可用"
        return 0
    fi
    
    local ports=()
    local ss_output=$(ss -tulnp 2>/dev/null || echo "")
    
    if [ -z "$ss_output" ]; then
        warning "无法获取监听端口信息"
        return 0
    fi
    
    while IFS= read -r line; do
        if [[ "$line" =~ ^(Netid|State) ]]; then
            continue
        fi
        
        if ! echo "$line" | grep -qE '(LISTEN|UNCONN)'; then
            continue
        fi
        
        local port=$(echo "$line" | awk '{print $5}' | grep -oE '[0-9]+$' || echo "")
        local process_match=$(echo "$line" | grep -oE 'users:\(\("([^"]+)"' || echo "")
        local process=$(echo "$process_match" | grep -oE '"[^"]+"' | tr -d '"' | head -1 || echo "")
        
        if [ -z "$port" ] || [ "$port" = "$SSH_PORT" ]; then
            continue
        fi
        
        local is_proxy=false
        if [ -n "$process" ]; then
            for proxy in "${PROXY_CORE_PROCESSES[@]}"; do
                if echo "$process" | grep -q "$proxy"; then
                    is_proxy=true
                    break
                fi
            done
        fi
        
        if [ "$is_proxy" = true ] && ! is_internal_service_port "$port"; then
            local addr=$(echo "$line" | awk '{print $5}')
            if ! echo "$addr" | grep -qE '^(127\.|::1|\[::1\])'; then
                ports+=("$port")
                debug_log "检测到端口: $port 进程: $process"
            fi
        fi
    done <<< "$ss_output"
    
    if [ ${#ports[@]} -gt 0 ]; then
        local unique=($(printf '%s\n' "${ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique[@]}")
        success "检测到 ${#unique[@]} 个监听端口"
    fi
    
    return 0
}

# 检查端口是否为内部服务
is_internal_service_port() {
    local port="$1"
    for internal in "${INTERNAL_SERVICE_PORTS[@]}"; do
        if [ "$port" = "$internal" ]; then
            return 0
        fi
    done
    return 1
}

# 端口安全检查
is_port_safe() {
    local port="$1"
    
    for blacklist in "${BLACKLIST_PORTS[@]}"; do
        if [ "$port" = "$blacklist" ]; then
            return 1
        fi
    done
    
    if is_internal_service_port "$port"; then
        return 1
    fi
    
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    
    return 0
}

# 过滤并确认端口
filter_and_confirm_ports() {
    info "智能端口分析..."
    
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    
    local all=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    local safe=()
    local unsafe=()
    
    for port in "${all[@]}"; do
        if is_port_safe "$port"; then
            safe+=("$port")
        else
            unsafe+=("$port")
        fi
    done
    
    if [ ${#safe[@]} -gt 0 ]; then
        echo -e "\n${GREEN}✅ 将开放的端口:${RESET}"
        for port in "${safe[@]}"; do
            local is_default=false
            for def_port in "${DEFAULT_OPEN_PORTS[@]}"; do
                if [ "$port" = "$def_port" ]; then
                    is_default=true
                    break
                fi
            done
            
            if [ "$is_default" = true ]; then
                echo -e "  ${GREEN}✓ $port - 默认${RESET}"
            else
                echo -e "  ${GREEN}✓ $port${RESET}"
            fi
        done
    fi
    
    if [ ${#unsafe[@]} -gt 0 ]; then
        echo -e "\n${RED}❌ 已跳过的危险端口:${RESET}"
        for port in "${unsafe[@]}"; do
            echo -e "  ${RED}✗ $port${RESET}"
        done
    fi
    
    if [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -eq 0 ] && [ "$AUTO_MODE" = false ]; then
        read_with_timeout "\n${CYAN}配置端口转发功能吗？[y/N]${RESET}" 10 "N"
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            add_port_range_interactive
        fi
    fi
    
    if [ "$DRY_RUN" = false ] && [ "$AUTO_MODE" = false ]; then
        echo -e "\n${CYAN}📋 摘要:${RESET}"
        echo -e "  • 开放端口: ${#safe[@]} 个"
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "  • 端口转发: ${#NAT_RULES[@]} 条"
        fi
        
        read_with_timeout "\n${YELLOW}确认应用配置？[Y/n]${RESET}" 10 "Y"
        if [[ "$REPLY" =~ ^[Nn]$ ]]; then
            info "用户取消操作"
            exit 0
        fi
    fi
    
    DETECTED_PORTS=($(printf '%s\n' "${safe[@]}" | sort -nu))
    if [ ${#DETECTED_PORTS[@]} -eq 0 ]; then
        DETECTED_PORTS=("${DEFAULT_OPEN_PORTS[@]}")
    fi
    
    return 0
}

# 清理现有防火墙
cleanup_firewalls() {
    info "清理现有防火墙配置..."
    
    if [ "$DRY_RUN" = true ]; then
        return 0
    fi
    
    for service in ufw firewalld; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
        fi
    done
    
    nft flush ruleset 2>/dev/null || true
    
    if command -v iptables >/dev/null 2>&1; then
        iptables -P INPUT ACCEPT 2>/dev/null || true
        iptables -P FORWARD ACCEPT 2>/dev/null || true
        iptables -P OUTPUT ACCEPT 2>/dev/null || true
        iptables -F 2>/dev/null || true
        iptables -X 2>/dev/null || true
        iptables -t nat -F 2>/dev/null || true
        iptables -t nat -X 2>/dev/null || true
    fi
    
    success "防火墙清理完成"
    return 0
}

# 创建 nftables 基础结构
create_nftables_base() {
    if [ "$DRY_RUN" = true ]; then
        return 0
    fi
    
    info "创建 nftables 规则..."
    
    nft add table inet "$NFT_TABLE"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" "{ type filter hook input priority 0 ; policy drop ; }"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_FORWARD" "{ type filter hook forward priority 0 ; policy drop ; }"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_OUTPUT" "{ type filter hook output priority 0 ; policy accept ; }"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" "{ type nat hook prerouting priority -100 ; }"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_SSH"
    
    return 0
}

# 应用防火墙规则
apply_firewall_rules() {
    info "应用防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 规则预览已完成"
        return 0
    fi
    
    create_nftables_base
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" iif "lo" accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" ct state established,related accept
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" icmp type echo-request limit rate 10/second accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" icmpv6 type echo-request limit rate 10/second accept
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" ct state established,related accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" tcp dport "$SSH_PORT" limit rate 4/minute burst 4 packets accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" tcp dport "$SSH_PORT" drop
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport "$SSH_PORT" jump "$NFT_CHAIN_SSH"
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        local ports=$(printf '%s,' "${DETECTED_PORTS[@]}")
        ports="${ports%,}"
        nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport "{ $ports }" accept
        nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" udp dport "{ $ports }" accept
        success "已开放 ${#DETECTED_PORTS[@]} 个端口"
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        for rule in "${NAT_RULES[@]}"; do
            local range="${rule%->*}"
            local target="${rule##*->}"
            
            nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" tcp dport "$range" dnat to ":$target"
            nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" udp dport "$range" dnat to ":$target"
            nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport "$range" accept
            nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" udp dport "$range" accept
            
            success "端口转发: $range -> $target"
        done
    fi
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" limit rate 3/minute burst 3 packets log prefix '"fw-drop: "' level warn
    
    OPENED_PORTS=${#DETECTED_PORTS[@]}
    save_nftables_rules
    success "防火墙规则应用完成"
    return 0
}

# 保存规则
save_nftables_rules() {
    if [ "$DRY_RUN" = true ]; then
        return 0
    fi
    
    mkdir -p /etc/nftables.d
    nft list ruleset > /etc/nftables.conf
    
    cat > /etc/systemd/system/nftables-restore.service << 'EOF'
[Unit]
Description=Restore nftables rules
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/nftables.conf
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable nftables-restore.service >/dev/null 2>&1 || true
    
    success "规则已保存并配置开机自启"
    return 0
}

# 重置防火墙
reset_firewall() {
    echo -e "${YELLOW}🔄 重置防火墙${RESET}"
    
    if [ "$DRY_RUN" = false ] && [ "$AUTO_MODE" = false ]; then
        read_with_timeout "${RED}确认重置所有防火墙规则？[y/N]${RESET}" 10 "N"
        if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
            return 0
        fi
    fi
    
    if [ "$DRY_RUN" = false ]; then
        nft flush ruleset 2>/dev/null || true
        echo "" > /etc/nftables.conf 2>/dev/null || true
        systemctl disable nftables-restore.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/nftables-restore.service
        systemctl daemon-reload
        success "防火墙已重置"
    else
        info "[预览模式] 将重置防火墙"
    fi
    
    return 0
}

# 显示防火墙状态
show_firewall_status() {
    echo -e "${CYAN}🔍 防火墙状态${RESET}\n"
    
    if ! nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        warning "未找到防火墙规则表"
        return 1
    fi
    
    echo -e "${GREEN}📊 规则统计:${RESET}"
    local input_rules=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" 2>/dev/null | grep -c "accept\|drop" || echo "0")
    local nat_rules=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep -c "dnat to" || echo "0")
    echo -e "  INPUT 规则: $input_rules"
    echo -e "  NAT 规则: $nat_rules"
    
    echo -e "\n${GREEN}🔓 开放端口:${RESET}"
    local port_rules=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" 2>/dev/null | grep -E "(tcp|udp) dport" | grep "accept" || echo "")
    if [ -n "$port_rules" ]; then
        while read -r line; do
            local ports=$(echo "$line" | grep -oE 'dport \{[^}]+\}' | sed 's/dport //g' | tr -d '{}')
            if [ -z "$ports" ]; then
                ports=$(echo "$line" | grep -oE 'dport [0-9-]+' | sed 's/dport //g')
            fi
            local proto=$(echo "$line" | grep -oE "tcp|udp")
            if [ -n "$ports" ]; then
                echo -e "  • $ports - $proto"
            fi
        done <<< "$port_rules"
    else
        echo -e "  ${YELLOW}无开放端口${RESET}"
    fi
    
    echo -e "\n${GREEN}🔄 端口转发:${RESET}"
    local nat_output=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep "dnat to" || echo "")
    if [ -n "$nat_output" ]; then
        while read -r line; do
            local range=$(echo "$line" | grep -oE 'dport [0-9-]+' | sed 's/dport //g')
            local target=$(echo "$line" | grep -oE 'dnat to :[0-9]+' | sed 's/dnat to ://g')
            if [ -n "$range" ] && [ -n "$target" ]; then
                echo -e "  • $range → $target"
            fi
        done <<< "$nat_output"
    else
        echo -e "  ${YELLOW}无端口转发规则${RESET}"
    fi
    
    echo -e "\n${GREEN}🛡️  SSH 保护:${RESET}"
    if nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_SSH" 2>/dev/null | grep -q "limit rate"; then
        echo -e "  ${GREEN}✓ 已启用${RESET}"
    else
        echo -e "  ${YELLOW}⚠️  未启用${RESET}"
    fi
    
    return 0
}

# 显示最终状态
show_final_status() {
    echo -e "\n${GREEN}=================================="
    echo -e "🎉 防火墙配置完成！"
    echo -e "==================================${RESET}"
    
    echo -e "\n${CYAN}📊 配置摘要:${RESET}"
    echo -e "  ${GREEN}✓ 开放端口: $OPENED_PORTS 个${RESET}"
    echo -e "  ${GREEN}✓ SSH 端口: $SSH_PORT - 已保护${RESET}"
    echo -e "  ${GREEN}✓ 防火墙: nftables${RESET}"
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "  ${GREEN}✓ 端口转发: ${#NAT_RULES[@]} 条${RESET}"
    fi
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 开放端口列表:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            local is_default=false
            for def_port in "${DEFAULT_OPEN_PORTS[@]}"; do
                if [ "$port" = "$def_port" ]; then
                    is_default=true
                    break
                fi
            done
            
            if [ "$is_default" = true ]; then
                echo -e "  ${GREEN}• $port - TCP/UDP - 默认${RESET}"
            else
                echo -e "  ${GREEN}• $port - TCP/UDP${RESET}"
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${CYAN}🔄 端口转发规则:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            echo -e "  ${CYAN}• $rule${RESET}"
        done
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}🔍 预览模式，未实际修改${RESET}"
        return 0
    fi
    
    echo -e "\n${CYAN}🔧 常用命令:${RESET}"
    echo -e "  ${YELLOW}查看规则:${RESET} nft list ruleset"
    echo -e "  ${YELLOW}查看状态:${RESET} bash $0 --status"
    echo -e "  ${YELLOW}添加转发:${RESET} bash $0 --add-range"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash $0 --reset"
    
    echo -e "\n${GREEN}✅ 配置完成，服务器安全已启用！${RESET}"
    
    return 0
}

# 主函数
main() {
    set +e
    trap 'echo -e "\n${RED}操作被中断${RESET}"; exit 130' INT TERM
    
    parse_arguments "$@"
    
    echo -e "\n${CYAN}🚀 开始配置...${RESET}"
    
    if ! check_system; then
        error_exit "系统环境检查失败"
    fi
    
    if ! detect_ssh_port; then
        error_exit "SSH 端口检测失败"
    fi
    
    if ! detect_existing_nat_rules; then
        warning "NAT 规则检测失败，继续..."
    fi
    
    if ! cleanup_firewalls; then
        error_exit "防火墙清理失败"
    fi
    
    if ! detect_proxy_processes; then
        warning "未检测到代理进程，将使用默认配置"
    fi
    
    if ! parse_config_ports; then
        warning "配置文件解析失败，继续..."
    fi
    
    if ! detect_listening_ports; then
        warning "监听端口检测失败，继续..."
    fi
    
    if ! filter_and_confirm_ports; then
        error_exit "端口过滤失败"
    fi
    
    if ! apply_firewall_rules; then
        error_exit "防火墙规则应用失败"
    fi
    
    show_final_status
}

# 执行主函数
main "$@"

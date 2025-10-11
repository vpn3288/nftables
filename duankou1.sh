#!/bin/bash
# 不要在第一个错误时退出
set +e

# 颜色定义
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

# 脚本信息
SCRIPT_VERSION="2.2.0"
SCRIPT_NAME="精确代理端口防火墙管理脚本（nftables 优化版）"

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
NFT_TABLE="proxy_firewall"
NFT_CHAIN_INPUT="input_chain"
NFT_CHAIN_FORWARD="forward_chain"
NFT_CHAIN_OUTPUT="output_chain"
NFT_CHAIN_PREROUTING="prerouting_chain"
NFT_CHAIN_SSH="ssh_protection"

# 默认永久开放端口
DEFAULT_OPEN_PORTS=(80 443)

# 代理核心进程
PROXY_CORE_PROCESSES=(
    "xray" "v2ray" "sing-box" "singbox"
    "hysteria" "hysteria2" "tuic" "juicity"
    "hiddify" "x-ui" "3x-ui" "v2-ui"
    "trojan" "trojan-go"
    "shadowsocks" "ss-server" "ss-rust"
    "brook" "gost" "naive" "clash" "mihomo"
)

# 内部服务端口（不应暴露）
INTERNAL_SERVICE_PORTS=(
    8181 10085 10086 9090 3000 8000
    54321 62789
)

# 危险端口黑名单
BLACKLIST_PORTS=(
    22 23 25 53 69 111 135 137 138 139 445 514 631
    1433 1521 3306 5432 6379 27017
    3389 5900 5901
)

# 辅助函数
debug_log() { 
    [ "$DEBUG_MODE" = true ] && echo -e "${BLUE}[调试] $1${RESET}"
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
精确代理端口防火墙管理脚本 v2.2.0（nftables 优化版）

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

支持的代理面板/软件:
    ✓ Hiddify Manager/Panel
    ✓ 3X-UI / X-UI
    ✓ Xray / V2Ray
    ✓ Sing-box
    ✓ Hysteria / Hysteria2
    ✓ Trojan 系列
    ✓ Shadowsocks 系列

安全功能:
    ✓ 精确端口识别
    ✓ 自动过滤内部服务端口
    ✓ SSH 暴力破解防护
    ✓ 高性能 nftables 防火墙
    ✓ NAT 端口转发支持

EOF
}

# 超时读取函数（防止卡住）
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
            *) error_exit "未知参数: $1\n使用 --help 查看帮助" ;;
        esac
    done
}

# 检查系统环境
check_system() {
    info "检查系统环境..."
    
    # 检查必需工具
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
                error_exit "无法自动安装 nftables，请手动安装"
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
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y iproute >/dev/null 2>&1
            fi
        fi
    fi
    
    # 加载 nftables 内核模块
    if [ "$DRY_RUN" = false ]; then
        modprobe nf_tables 2>/dev/null || true
    fi
    
    success "系统环境检查完成"
}

# 检测 SSH 端口
detect_ssh_port() {
    debug_log "检测 SSH 端口..."
    
    local ssh_port=""
    
    # 方法1: 从监听端口检测
    if command -v ss >/dev/null 2>&1; then
        ssh_port=$(ss -tlnp 2>/dev/null | grep -i 'sshd' | head -1 | awk '{print $4}' | grep -oE '[0-9]+

# 检测现有的 NAT 规则
detect_existing_nat_rules() {
    info "检测现有端口转发规则..."
    
    local nat_rules=()
    
    # 检查 nftables NAT 规则
    if command -v nft >/dev/null 2>&1; then
        # 获取所有表
        local tables=$(nft list tables 2>/dev/null || true)
        
        if [ -n "$tables" ]; then
            while read -r family table; do
                [ -z "$table" ] && continue
                
                # 列出表中的 DNAT 规则
                local nat_output=$(nft list table $family $table 2>/dev/null | grep "dnat to" || true)
                
                if [ -n "$nat_output" ]; then
                    while IFS= read -r line; do
                        # 提取端口范围和目标端口
                        if [[ "$line" =~ dport[[:space:]]+([0-9]+)-([0-9]+).*dnat[[:space:]]+to[[:space:]]+:([0-9]+) ]]; then
                            local start="${BASH_REMATCH[1]}"
                            local end="${BASH_REMATCH[2]}"
                            local target="${BASH_REMATCH[3]}"
                            nat_rules+=("$start-$end->$target")
                            debug_log "发现 NAT 规则: $start-$end -> $target"
                        fi
                    done <<< "$nat_output"
                fi
            done <<< "$tables"
        fi
    fi
    
    if [ ${#nat_rules[@]} -gt 0 ]; then
        NAT_RULES=($(printf '%s\n' "${nat_rules[@]}" | sort -u))
        echo -e "\n${GREEN}🔄 现有端口转发规则:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            echo -e "  ${GREEN}• $rule${RESET}"
        done
        
        # 添加目标端口到检测端口列表
        for rule in "${NAT_RULES[@]}"; do
            local target="${rule##*->}"
            [ -n "$target" ] && DETECTED_PORTS+=("$target")
        done
        
        success "检测到 ${#NAT_RULES[@]} 条端口转发规则"
    else
        info "未检测到现有端口转发规则"
    fi
    
    return 0
}

# 单独的NAT规则清理函数
clean_nat_rules_only() {
    echo -e "${YELLOW}🔄 清理重复的NAT规则${RESET}"
    
    if [ "$DRY_RUN" = false ] && [ "$AUTO_MODE" = false ]; then
        read_with_timeout "${YELLOW}确认清理所有NAT规则吗？[y/N]${RESET}" 10 "N"
        if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
            info "清理操作已取消"
            return 0
        fi
    fi
    
    info "正在清理NAT规则..."
    
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
}

# 交互式端口范围添加
add_port_range_interactive() {
    echo -e "${CYAN}🔧 配置端口转发规则${RESET}"
    echo -e "${YELLOW}示例: 16820-16888 转发到 16801${RESET}"
    
    while true; do
        echo -e "\n${CYAN}输入端口范围（格式: 起始-结束）:${RESET}"
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
}

# 检测代理进程
detect_proxy_processes() {
    info "检测代理服务进程..."
    
    local found=()
    for process in "${PROXY_CORE_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found+=("$process")
            debug_log "发现: $process"
        fi
    done
    
    if [ ${#found[@]} -gt 0 ]; then
        success "检测到代理进程: ${found[*]}"
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
        "/opt/hiddify-manager/hiddify-panel/config.py"
    )
    
    local ports=()
    for file in "${config_files[@]}"; do
        [ ! -f "$file" ] && continue
        
        debug_log "分析: $file"
        
        # JSON 文件 - 简单提取端口
        if [[ "$file" =~ \.json$ ]]; then
            local found=$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' "$file" 2>/dev/null | grep -oE '[0-9]+' | sort -nu || true)
            if [ -n "$found" ]; then
                while read -r port; do
                    [ -n "$port" ] && ports+=("$port")
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
    
    local ports=()
    
    while IFS= read -r line; do
        [[ "$line" =~ (LISTEN|UNCONN) ]] || continue
        
        local port=$(echo "$line" | awk '{print $5}' | grep -oE '[0-9]+$')
        local process=$(echo "$line" | grep -oE 'users:\(\("([^"]+)"' | grep -oE '"[^"]+"' | tr -d '"' | head -1)
        
        [ -z "$port" ] || [ "$port" = "$SSH_PORT" ] && continue
        
        # 检查是否为代理相关进程
        local is_proxy=false
        for proxy in "${PROXY_CORE_PROCESSES[@]}"; do
            if [[ "$process" == *"$proxy"* ]]; then
                is_proxy=true
                break
            fi
        done
        
        if [ "$is_proxy" = true ] && ! is_internal_service_port "$port"; then
            # 检查绑定地址（排除 localhost）
            local addr=$(echo "$line" | awk '{print $5}')
            if [[ ! "$addr" =~ ^(127\.|::1|\[::1\]) ]]; then
                ports+=("$port")
                debug_log "检测到: $port ($process)"
            fi
        fi
    done <<< "$(ss -tulnp 2>/dev/null)"
    
    if [ ${#ports[@]} -gt 0 ]; then
        local unique=($(printf '%s\n' "${ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique[@]}")
        success "检测到 ${#unique[@]} 个监听端口"
    fi
}

# 检查端口是否为内部服务
is_internal_service_port() {
    local port="$1"
    for internal in "${INTERNAL_SERVICE_PORTS[@]}"; do
        [ "$port" = "$internal" ] && return 0
    done
    return 1
}

# 端口安全检查
is_port_safe() {
    local port="$1"
    
    # 检查黑名单
    for blacklist in "${BLACKLIST_PORTS[@]}"; do
        [ "$port" = "$blacklist" ] && return 1
    done
    
    # 检查内部服务
    is_internal_service_port "$port" && return 1
    
    # 检查范围
    [ "$port" -lt 1 ] || [ "$port" -gt 65535 ] && return 1
    
    return 0
}

# 过滤并确认端口
filter_and_confirm_ports() {
    info "智能端口分析..."
    
    # 添加默认端口
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
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}✓ $port${RESET} (默认)"
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
    
    # 询问是否配置端口转发
    if [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -eq 0 ] && [ "$AUTO_MODE" = false ]; then
        read_with_timeout "\n${CYAN}配置端口转发功能吗？[y/N]${RESET}" 10 "N"
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            add_port_range_interactive
        fi
    fi
    
    # 最终确认
    if [ "$DRY_RUN" = false ] && [ "$AUTO_MODE" = false ]; then
        echo -e "\n${CYAN}📋 摘要:${RESET}"
        echo -e "  • 开放端口: ${#safe[@]} 个"
        [ ${#NAT_RULES[@]} -gt 0 ] && echo -e "  • 端口转发: ${#NAT_RULES[@]} 条"
        
        read_with_timeout "\n${YELLOW}确认应用配置？[Y/n]${RESET}" 10 "Y"
        if [[ "$REPLY" =~ ^[Nn]$ ]]; then
            info "用户取消操作"
            exit 0
        fi
    fi
    
    DETECTED_PORTS=($(printf '%s\n' "${safe[@]}" | sort -nu))
    [ ${#DETECTED_PORTS[@]} -eq 0 ] && DETECTED_PORTS=("${DEFAULT_OPEN_PORTS[@]}")
    
    return 0
}

# 清理现有防火墙
cleanup_firewalls() {
    info "清理现有防火墙配置..."
    
    [ "$DRY_RUN" = true ] && return 0
    
    # 停用其他防火墙服务
    for service in ufw firewalld; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
        fi
    done
    
    # 清理 nftables
    nft flush ruleset 2>/dev/null || true
    
    # 清理 iptables（兼容性）
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
}

# 创建 nftables 基础结构
create_nftables_base() {
    [ "$DRY_RUN" = true ] && return 0
    
    info "创建 nftables 规则..."
    
    nft add table inet "$NFT_TABLE"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" { type filter hook input priority 0 \; policy drop \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_FORWARD" { type filter hook forward priority 0 \; policy drop \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_OUTPUT" { type filter hook output priority 0 \; policy accept \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" { type nat hook prerouting priority -100 \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_SSH"
}

# 应用防火墙规则
apply_firewall_rules() {
    info "应用防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 规则预览已完成"
        return 0
    fi
    
    create_nftables_base
    
    # 基本规则
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" iif "lo" accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" ct state established,related accept
    
    # ICMP
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" icmp type echo-request limit rate 10/second accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" icmpv6 type echo-request limit rate 10/second accept
    
    # SSH 保护
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" ct state established,related accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" tcp dport "$SSH_PORT" limit rate 4/minute burst 4 packets accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" tcp dport "$SSH_PORT" drop
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport "$SSH_PORT" jump "$NFT_CHAIN_SSH"
    
    # 开放代理端口
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        local ports=$(IFS=','; echo "${DETECTED_PORTS[*]}")
        nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport { $ports } accept
        nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" udp dport { $ports } accept
        info "已开放 ${#DETECTED_PORTS[@]} 个端口"
    fi
    
    # NAT 规则
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
    
    # 日志
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" limit rate 3/minute burst 3 packets log prefix \"fw-drop: \" level warn
    
    OPENED_PORTS=${#DETECTED_PORTS[@]}
    save_nftables_rules
    success "防火墙规则应用完成"
}

# 保存规则
save_nftables_rules() {
    [ "$DRY_RUN" = true ] && return 0
    
    mkdir -p /etc/nftables.d
    nft list ruleset > /etc/nftables.conf
    
    # 创建服务
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
}

# 重置防火墙
reset_firewall() {
    echo -e "${YELLOW}🔄 重置防火墙${RESET}"
    
    if [ "$DRY_RUN" = false ] && [ "$AUTO_MODE" = false ]; then
        read_with_timeout "${RED}确认重置所有防火墙规则？[y/N]${RESET}" 10 "N"
        [[ ! "$REPLY" =~ ^[Yy]$ ]] && return 0
    fi
    
    if [ "$DRY_RUN" = false ]; then
        nft flush ruleset 2>/dev/null || true
        > /etc/nftables.conf 2>/dev/null || true
        systemctl disable nftables-restore.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/nftables-restore.service
        systemctl daemon-reload
        success "防火墙已重置"
    else
        info "[预览模式] 将重置防火墙"
    fi
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
    nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" 2>/dev/null | grep -E "(tcp|udp) dport" | grep "accept" | while read -r line; do
        local ports=$(echo "$line" | grep -oE "dport \{[^}]+\}" | sed 's/dport //g' | tr -d '{}')
        [ -z "$ports" ] && ports=$(echo "$line" | grep -oE "dport [0-9-]+" | sed 's/dport //g')
        local proto=$(echo "$line" | grep -oE "tcp|udp")
        [ -n "$ports" ] && echo -e "  • $ports ($proto)"
    done
    
    echo -e "\n${GREEN}🔄 端口转发:${RESET}"
    local nat_count=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep -c "dnat to" || echo "0")
    if [ "$nat_count" -gt 0 ]; then
        nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep "dnat to" | while read -r line; do
            local range=$(echo "$line" | grep -oE "dport [0-9-]+" | sed 's/dport //g')
            local target=$(echo "$line" | grep -oE "dnat to :[0-9]+" | sed 's/dnat to ://g')
            [ -n "$range" ] && [ -n "$target" ] && echo -e "  • $range → $target"
        done
    else
        echo -e "  ${YELLOW}无端口转发规则${RESET}"
    fi
    
    echo -e "\n${GREEN}🛡️  SSH 保护:${RESET}"
    if nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_SSH" 2>/dev/null | grep -q "limit rate"; then
        echo -e "  ${GREEN}✓ 已启用${RESET}"
    else
        echo -e "  ${YELLOW}⚠️  未启用${RESET}"
    fi
}

# 显示最终状态
show_final_status() {
    echo -e "\n${GREEN}=================================="
    echo -e "🎉 防火墙配置完成！"
    echo -e "==================================${RESET}"
    
    echo -e "\n${CYAN}📊 配置摘要:${RESET}"
    echo -e "  ${GREEN}✓ 开放端口: $OPENED_PORTS 个${RESET}"
    echo -e "  ${GREEN}✓ SSH 端口: $SSH_PORT (已保护)${RESET}"
    echo -e "  ${GREEN}✓ 防火墙: nftables${RESET}"
    [ ${#NAT_RULES[@]} -gt 0 ] && echo -e "  ${GREEN}✓ 端口转发: ${#NAT_RULES[@]} 条${RESET}"
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 开放端口列表:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}• $port (TCP/UDP) - 默认${RESET}"
            else
                echo -e "  ${GREEN}• $port (TCP/UDP)${RESET}"
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${CYAN}🔄 端口转发规则:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            echo -e "  ${CYAN}• $rule${RESET}"
        done
    fi
    
    [ "$DRY_RUN" = true ] && echo -e "\n${CYAN}🔍 预览模式，未实际修改${RESET}" && return 0
    
    echo -e "\n${CYAN}🔧 常用命令:${RESET}"
    echo -e "  ${YELLOW}查看规则:${RESET} nft list ruleset"
    echo -e "  ${YELLOW}查看状态:${RESET} bash $0 --status"
    echo -e "  ${YELLOW}添加转发:${RESET} bash $0 --add-range"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash $0 --reset"
    
    echo -e "\n${GREEN}✅ 配置完成，服务器安全已启用！${RESET}"
}

# 主函数
main() {
    # 设置错误处理
    set +e  # 不要在错误时退出
    trap 'echo -e "\n${RED}操作被中断${RESET}"; exit 130' INT TERM
    
    parse_arguments "$@"
    
    echo -e "\n${CYAN}🚀 开始配置...${RESET}"
    
    # 逐步执行，添加错误检查
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
main "$@" || true)
    fi
    
    # 方法2: 从配置文件检测
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] && [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -E '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1 || true)
    fi
    
    # 方法3: 从进程信息检测
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]]; then
        ssh_port=$(ps aux | grep -i '[s]shd' | grep -oE '\-p [0-9]+' | awk '{print $2}' | head -1 || true)
    fi
    
    # 默认端口
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] || [ -z "$ssh_port" ]; then
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
        while IFS= read -r line; do
            if [[ "$line" =~ tcp\ dport\ ([0-9]+)-([0-9]+).*dnat\ to\ :([0-9]+) ]]; then
                local start="${BASH_REMATCH[1]}"
                local end="${BASH_REMATCH[2]}"
                local target="${BASH_REMATCH[3]}"
                nat_rules+=("$start-$end->$target")
                debug_log "发现 NAT 规则: $start-$end -> $target"
            fi
        done <<< "$(nft list tables 2>/dev/null | while read -r family table; do
            nft list table $family $table 2>/dev/null | grep "dnat to"
        done)"
    fi
    
    if [ ${#nat_rules[@]} -gt 0 ]; then
        NAT_RULES=($(printf '%s\n' "${nat_rules[@]}" | sort -u))
        echo -e "\n${GREEN}🔄 现有端口转发规则:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            echo -e "  ${GREEN}• $rule${RESET}"
        done
        
        # 添加目标端口到检测端口列表
        for rule in "${NAT_RULES[@]}"; do
            local target="${rule##*->}"
            DETECTED_PORTS+=("$target")
        done
        
        success "检测到 ${#NAT_RULES[@]} 条端口转发规则"
    else
        info "未检测到现有端口转发规则"
    fi
}

# 单独的NAT规则清理函数
clean_nat_rules_only() {
    echo -e "${YELLOW}🔄 清理重复的NAT规则${RESET}"
    
    if [ "$DRY_RUN" = false ] && [ "$AUTO_MODE" = false ]; then
        read_with_timeout "${YELLOW}确认清理所有NAT规则吗？[y/N]${RESET}" 10 "N"
        if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
            info "清理操作已取消"
            return 0
        fi
    fi
    
    info "正在清理NAT规则..."
    
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
}

# 交互式端口范围添加
add_port_range_interactive() {
    echo -e "${CYAN}🔧 配置端口转发规则${RESET}"
    echo -e "${YELLOW}示例: 16820-16888 转发到 16801${RESET}"
    
    while true; do
        echo -e "\n${CYAN}输入端口范围（格式: 起始-结束）:${RESET}"
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
}

# 检测代理进程
detect_proxy_processes() {
    info "检测代理服务进程..."
    
    local found=()
    for process in "${PROXY_CORE_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found+=("$process")
            debug_log "发现: $process"
        fi
    done
    
    if [ ${#found[@]} -gt 0 ]; then
        success "检测到代理进程: ${found[*]}"
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
        "/opt/hiddify-manager/hiddify-panel/config.py"
    )
    
    local ports=()
    for file in "${config_files[@]}"; do
        [ ! -f "$file" ] && continue
        
        debug_log "分析: $file"
        
        # JSON 文件
        if [[ "$file" =~ \.json$ ]]; then
            # 简单的端口提取，不依赖 jq
            local found=$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' "$file" 2>/dev/null | grep -oE '[0-9]+' | sort -nu)
            [ -n "$found" ] && ports+=($found)
        fi
    done
    
    if [ ${#ports[@]} -gt 0 ]; then
        local unique=($(printf '%s\n' "${ports[@]}" | sort -nu))
        for port in "${unique[@]}"; do
            if ! is_internal_service_port "$port"; then
                DETECTED_PORTS+=("$port")
            fi
        done
        success "从配置文件解析到 ${#unique[@]} 个端口"
    fi
}

# 检测监听端口
detect_listening_ports() {
    info "检测当前监听端口..."
    
    local ports=()
    
    while IFS= read -r line; do
        [[ "$line" =~ (LISTEN|UNCONN) ]] || continue
        
        local port=$(echo "$line" | awk '{print $5}' | grep -oE '[0-9]+$')
        local process=$(echo "$line" | grep -oE 'users:\(\("([^"]+)"' | grep -oE '"[^"]+"' | tr -d '"' | head -1)
        
        [ -z "$port" ] || [ "$port" = "$SSH_PORT" ] && continue
        
        # 检查是否为代理相关进程
        local is_proxy=false
        for proxy in "${PROXY_CORE_PROCESSES[@]}"; do
            if [[ "$process" == *"$proxy"* ]]; then
                is_proxy=true
                break
            fi
        done
        
        if [ "$is_proxy" = true ] && ! is_internal_service_port "$port"; then
            # 检查绑定地址（排除 localhost）
            local addr=$(echo "$line" | awk '{print $5}')
            if [[ ! "$addr" =~ ^(127\.|::1|\[::1\]) ]]; then
                ports+=("$port")
                debug_log "检测到: $port ($process)"
            fi
        fi
    done <<< "$(ss -tulnp 2>/dev/null)"
    
    if [ ${#ports[@]} -gt 0 ]; then
        local unique=($(printf '%s\n' "${ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique[@]}")
        success "检测到 ${#unique[@]} 个监听端口"
    fi
}

# 检查端口是否为内部服务
is_internal_service_port() {
    local port="$1"
    for internal in "${INTERNAL_SERVICE_PORTS[@]}"; do
        [ "$port" = "$internal" ] && return 0
    done
    return 1
}

# 端口安全检查
is_port_safe() {
    local port="$1"
    
    # 检查黑名单
    for blacklist in "${BLACKLIST_PORTS[@]}"; do
        [ "$port" = "$blacklist" ] && return 1
    done
    
    # 检查内部服务
    is_internal_service_port "$port" && return 1
    
    # 检查范围
    [ "$port" -lt 1 ] || [ "$port" -gt 65535 ] && return 1
    
    return 0
}

# 过滤并确认端口
filter_and_confirm_ports() {
    info "智能端口分析..."
    
    # 添加默认端口
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
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}✓ $port${RESET} (默认)"
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
    
    # 询问是否配置端口转发
    if [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -eq 0 ] && [ "$AUTO_MODE" = false ]; then
        read_with_timeout "\n${CYAN}配置端口转发功能吗？[y/N]${RESET}" 10 "N"
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            add_port_range_interactive
        fi
    fi
    
    # 最终确认
    if [ "$DRY_RUN" = false ] && [ "$AUTO_MODE" = false ]; then
        echo -e "\n${CYAN}📋 摘要:${RESET}"
        echo -e "  • 开放端口: ${#safe[@]} 个"
        [ ${#NAT_RULES[@]} -gt 0 ] && echo -e "  • 端口转发: ${#NAT_RULES[@]} 条"
        
        read_with_timeout "\n${YELLOW}确认应用配置？[Y/n]${RESET}" 10 "Y"
        if [[ "$REPLY" =~ ^[Nn]$ ]]; then
            info "用户取消操作"
            exit 0
        fi
    fi
    
    DETECTED_PORTS=($(printf '%s\n' "${safe[@]}" | sort -nu))
    [ ${#DETECTED_PORTS[@]} -eq 0 ] && DETECTED_PORTS=("${DEFAULT_OPEN_PORTS[@]}")
    
    return 0
}

# 清理现有防火墙
cleanup_firewalls() {
    info "清理现有防火墙配置..."
    
    [ "$DRY_RUN" = true ] && return 0
    
    # 停用其他防火墙服务
    for service in ufw firewalld; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
        fi
    done
    
    # 清理 nftables
    nft flush ruleset 2>/dev/null || true
    
    # 清理 iptables（兼容性）
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
}

# 创建 nftables 基础结构
create_nftables_base() {
    [ "$DRY_RUN" = true ] && return 0
    
    info "创建 nftables 规则..."
    
    nft add table inet "$NFT_TABLE"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" { type filter hook input priority 0 \; policy drop \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_FORWARD" { type filter hook forward priority 0 \; policy drop \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_OUTPUT" { type filter hook output priority 0 \; policy accept \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" { type nat hook prerouting priority -100 \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_SSH"
}

# 应用防火墙规则
apply_firewall_rules() {
    info "应用防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 规则预览已完成"
        return 0
    fi
    
    create_nftables_base
    
    # 基本规则
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" iif "lo" accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" ct state established,related accept
    
    # ICMP
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" icmp type echo-request limit rate 10/second accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" icmpv6 type echo-request limit rate 10/second accept
    
    # SSH 保护
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" ct state established,related accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" tcp dport "$SSH_PORT" limit rate 4/minute burst 4 packets accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" tcp dport "$SSH_PORT" drop
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport "$SSH_PORT" jump "$NFT_CHAIN_SSH"
    
    # 开放代理端口
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        local ports=$(IFS=','; echo "${DETECTED_PORTS[*]}")
        nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport { $ports } accept
        nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" udp dport { $ports } accept
        info "已开放 ${#DETECTED_PORTS[@]} 个端口"
    fi
    
    # NAT 规则
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
    
    # 日志
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" limit rate 3/minute burst 3 packets log prefix \"fw-drop: \" level warn
    
    OPENED_PORTS=${#DETECTED_PORTS[@]}
    save_nftables_rules
    success "防火墙规则应用完成"
}

# 保存规则
save_nftables_rules() {
    [ "$DRY_RUN" = true ] && return 0
    
    mkdir -p /etc/nftables.d
    nft list ruleset > /etc/nftables.conf
    
    # 创建服务
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
}

# 重置防火墙
reset_firewall() {
    echo -e "${YELLOW}🔄 重置防火墙${RESET}"
    
    if [ "$DRY_RUN" = false ] && [ "$AUTO_MODE" = false ]; then
        read_with_timeout "${RED}确认重置所有防火墙规则？[y/N]${RESET}" 10 "N"
        [[ ! "$REPLY" =~ ^[Yy]$ ]] && return 0
    fi
    
    if [ "$DRY_RUN" = false ]; then
        nft flush ruleset 2>/dev/null || true
        > /etc/nftables.conf 2>/dev/null || true
        systemctl disable nftables-restore.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/nftables-restore.service
        systemctl daemon-reload
        success "防火墙已重置"
    else
        info "[预览模式] 将重置防火墙"
    fi
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
    nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" 2>/dev/null | grep -E "(tcp|udp) dport" | grep "accept" | while read -r line; do
        local ports=$(echo "$line" | grep -oE "dport \{[^}]+\}" | sed 's/dport //g' | tr -d '{}')
        [ -z "$ports" ] && ports=$(echo "$line" | grep -oE "dport [0-9-]+" | sed 's/dport //g')
        local proto=$(echo "$line" | grep -oE "tcp|udp")
        [ -n "$ports" ] && echo -e "  • $ports ($proto)"
    done
    
    echo -e "\n${GREEN}🔄 端口转发:${RESET}"
    local nat_count=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep -c "dnat to" || echo "0")
    if [ "$nat_count" -gt 0 ]; then
        nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep "dnat to" | while read -r line; do
            local range=$(echo "$line" | grep -oE "dport [0-9-]+" | sed 's/dport //g')
            local target=$(echo "$line" | grep -oE "dnat to :[0-9]+" | sed 's/dnat to ://g')
            [ -n "$range" ] && [ -n "$target" ] && echo -e "  • $range → $target"
        done
    else
        echo -e "  ${YELLOW}无端口转发规则${RESET}"
    fi
    
    echo -e "\n${GREEN}🛡️  SSH 保护:${RESET}"
    if nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_SSH" 2>/dev/null | grep -q "limit rate"; then
        echo -e "  ${GREEN}✓ 已启用${RESET}"
    else
        echo -e "  ${YELLOW}⚠️  未启用${RESET}"
    fi
}

# 显示最终状态
show_final_status() {
    echo -e "\n${GREEN}=================================="
    echo -e "🎉 防火墙配置完成！"
    echo -e "==================================${RESET}"
    
    echo -e "\n${CYAN}📊 配置摘要:${RESET}"
    echo -e "  ${GREEN}✓ 开放端口: $OPENED_PORTS 个${RESET}"
    echo -e "  ${GREEN}✓ SSH 端口: $SSH_PORT (已保护)${RESET}"
    echo -e "  ${GREEN}✓ 防火墙: nftables${RESET}"
    [ ${#NAT_RULES[@]} -gt 0 ] && echo -e "  ${GREEN}✓ 端口转发: ${#NAT_RULES[@]} 条${RESET}"
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 开放端口列表:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}• $port (TCP/UDP) - 默认${RESET}"
            else
                echo -e "  ${GREEN}• $port (TCP/UDP)${RESET}"
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${CYAN}🔄 端口转发规则:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            echo -e "  ${CYAN}• $rule${RESET}"
        done
    fi
    
    [ "$DRY_RUN" = true ] && echo -e "\n${CYAN}🔍 预览模式，未实际修改${RESET}" && return 0
    
    echo -e "\n${CYAN}🔧 常用命令:${RESET}"
    echo -e "  ${YELLOW}查看规则:${RESET} nft list ruleset"
    echo -e "  ${YELLOW}查看状态:${RESET} bash $0 --status"
    echo -e "  ${YELLOW}添加转发:${RESET} bash $0 --add-range"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash $0 --reset"
    
    echo -e "\n${GREEN}✅ 配置完成，服务器安全已启用！${RESET}"
}

# 主函数
main() {
    trap 'echo -e "\n${RED}操作被中断${RESET}"; exit 130' INT TERM
    
    parse_arguments "$@"
    
    echo -e "\n${CYAN}🚀 开始配置...${RESET}"
    
    check_system
    detect_ssh_port
    detect_existing_nat_rules
    cleanup_firewalls
    
    detect_proxy_processes || warning "未检测到代理进程，将使用默认配置"
    
    parse_config_ports
    detect_listening_ports
    filter_and_confirm_ports
    
    apply_firewall_rules
    show_final_status
}

# 执行主函数
main "$@"

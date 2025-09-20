#!/bin/bash
set -e

# 颜色定义
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

# 脚本信息
SCRIPT_VERSION="2.2.1"
SCRIPT_NAME="智能代理端口防火墙管理工具"

echo "============================================"
echo -e "   ${CYAN}${SCRIPT_NAME} v${SCRIPT_VERSION}${RESET}   "
echo "============================================"
echo "专为 Hiddify、3X-UI、X-UI、Sing-box、Xray、WARP 等代理工具优化"
echo "使用现代化 nftables 防火墙技术，安全可靠"

# 权限检查
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}[错误] 需要 root 权限运行此脚本${RESET}"
    exit 1
fi

# 全局变量
DEBUG_MODE=false
DRY_RUN=false
SSH_PORT=""
DETECTED_PORTS=()
PORT_RANGES=()
NAT_RULES=()
OPENED_PORTS=0
NFTABLES_TABLE="proxy_firewall"

# 默认永久开放端口
DEFAULT_OPEN_PORTS=(80 443)

# 代理核心进程
PROXY_CORE_PROCESSES=(
    "xray" "v2ray" "sing-box" "singbox" "sing_box"
    "hysteria" "hysteria2" "tuic" "juicity" "shadowtls"
    "hiddify" "hiddify-panel" "hiddify-manager"
    "x-ui" "3x-ui" "v2-ui" "v2rayA" "v2raya"
    "trojan" "trojan-go" "trojan-plus"
    "shadowsocks-rust" "ss-server" "shadowsocks-libev" "go-shadowsocks2"
    "brook" "gost" "naive" "clash" "clash-meta" "mihomo"
    "warp-svc" "warp" "cloudflare-warp" "warp-cli"
)

# Web 面板进程
WEB_PANEL_PROCESSES=(
    "nginx" "caddy" "apache2" "httpd" "haproxy" "envoy"
)

# WARP 常用端口
WARP_COMMON_PORTS=(
    "2408" "500" "1701" "4500"
    "51820" "51821"
    "38001" "38002"
)

# 内部服务端口（不应暴露）
INTERNAL_SERVICE_PORTS=(
    8181 10085 10086 9090 3000 3001 8000 8001
    10080 10081 10082 10083 10084 10085 10086 10087 10088 10089
    54321 62789
)

# 危险端口黑名单
BLACKLIST_PORTS=(
    22 23 25 53 69 111 135 137 138 139 445 514 631
    1433 1521 3306 5432 6379 27017
    3389 5900 5901 5902
    110 143 465 587 993 995
    8181 10085 10086
)

# 辅助函数
debug_log() { 
    if [ "$DEBUG_MODE" = true ]; then 
        echo -e "${BLUE}[调试] $1${RESET}"
    fi
}

error_exit() { 
    echo -e "${RED}[错误] $1${RESET}"
    exit 1
}

warning() { 
    echo -e "${YELLOW}[警告] $1${RESET}"
}

success() { 
    echo -e "${GREEN}[成功] $1${RESET}"
}

info() { 
    echo -e "${CYAN}[信息] $1${RESET}"
}

# 显示帮助信息
show_help() {
    cat << 'EOF'
智能代理端口防火墙管理工具 v2.2.1

为现代代理面板设计的智能端口管理工具

用法: bash script.sh [选项]

选项:
    --debug           显示详细调试信息
    --dry-run         预览模式，不实际修改防火墙
    --add-range       交互式端口范围添加
    --add-port        手动添加单个端口
    --reset           重置防火墙到默认状态
    --status          显示当前防火墙状态
    --help, -h        显示此帮助信息

支持的代理面板/软件:
    ✓ Hiddify Manager/Panel
    ✓ 3X-UI / X-UI
    ✓ Xray / V2Ray
    ✓ Sing-box
    ✓ Hysteria / Hysteria2
    ✓ Trojan-Go / Trojan
    ✓ Shadowsocks 系列
    ✓ Cloudflare WARP
    ✓ 其他主流代理工具

安全功能:
    ✓ 精确端口识别
    ✓ 自动过滤内部服务端口
    ✓ 危险端口过滤
    ✓ SSH 暴力破解防护
    ✓ 现代化 nftables 防火墙
    ✓ 每次运行前清理旧规则

EOF
}

# 解析参数
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug) DEBUG_MODE=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --add-range) add_port_range_interactive; exit 0 ;;
            --add-port) add_single_port_interactive; exit 0 ;;
            --reset) reset_firewall; exit 0 ;;
            --status) show_firewall_status; exit 0 ;;
            --help|-h) show_help; exit 0 ;;
            *) error_exit "未知参数: $1" ;;
        esac
    done
}

# 检查系统环境
check_system() {
    info "正在检查系统环境..."
    
    local tools=("nft" "ss")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        info "正在安装缺失的工具: ${missing_tools[*]}"
        if [ "$DRY_RUN" = false ]; then
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq && apt-get install -y nftables iproute2
            elif command -v yum >/dev/null 2>&1; then
                yum install -y nftables iproute
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y nftables iproute
            elif command -v pacman >/dev/null 2>&1; then
                pacman -S --noconfirm nftables iproute2
            else
                warning "无法自动安装依赖包，请手动安装: ${missing_tools[*]}"
            fi
        fi
    fi
    
    # 启动并启用 nftables 服务
    if [ "$DRY_RUN" = false ]; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl enable nftables >/dev/null 2>&1 || true
            systemctl start nftables >/dev/null 2>&1 || true
        fi
    fi
    
    success "系统环境检查完成"
}

# 检测 SSH 端口
detect_ssh_port() {
    info "正在检测 SSH 端口..."
    
    local ssh_port=$(ss -tlnp 2>/dev/null | grep -E ':22\b|sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -1)
    
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] && [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -i '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print $2}' | head -1)
    fi
    
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]]; then
        ssh_port="22"
    fi
    
    SSH_PORT="$ssh_port"
    info "检测到 SSH 端口: $SSH_PORT"
}

# 清理现有防火墙配置（每次运行前执行）
cleanup_existing_rules() {
    info "正在清理现有防火墙配置..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将清理现有防火墙配置"
        return 0
    fi
    
    # 停用其他防火墙服务
    for service in ufw firewalld iptables; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
            info "已禁用 $service"
        fi
    done
    
    # 重置 ufw 如果存在
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1 || true
    fi
    
    # 备份现有 nftables 规则
    local nft_backup="/tmp/nftables_backup_$(date +%Y%m%d_%H%M%S).nft"
    if nft list ruleset >/dev/null 2>&1; then
        nft list ruleset > "$nft_backup" 2>/dev/null || true
        info "已备份现有规则到: $nft_backup"
    fi
    
    # 清理现有的代理防火墙表
    if nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
        nft delete table inet "$NFTABLES_TABLE" 2>/dev/null || true
        info "已删除旧的防火墙表"
    fi
    
    success "防火墙清理完成"
}

# 检测代理服务
detect_proxy_processes() {
    info "正在检测代理服务..."
    
    local found_processes=()
    
    for process in "${PROXY_CORE_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found_processes+=("$process")
            debug_log "发现代理进程: $process"
        fi
    done
    
    for process in "${WEB_PANEL_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found_processes+=("$process")
            debug_log "发现 Web 面板进程: $process"
        fi
    done
    
    if [ ${#found_processes[@]} -gt 0 ]; then
        success "检测到代理服务: ${found_processes[*]}"
        return 0
    else
        warning "未检测到运行中的代理服务"
        return 1
    fi
}

# 检查绑定地址类型
check_bind_address() {
    local address="$1"
    
    if [[ "$address" =~ ^(\*|0\.0\.0\.0|\[::\]|::): ]]; then
        echo "public"
    elif [[ "$address" =~ ^(127\.|::1|\[::1\]): ]]; then
        echo "localhost"
    elif [[ "$address" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.): ]]; then
        echo "private"
    else
        echo "unknown"
    fi
}

# 解析配置文件端口
parse_config_ports() {
    info "正在解析代理配置文件..."
    
    local config_files=(
        "/etc/sing-box/config.json"
        "/opt/sing-box/config.json"
        "/usr/local/etc/sing-box/config.json"
        "/etc/xray/config.json"
        "/usr/local/etc/xray/config.json"
        "/etc/v2ray/config.json"
        "/usr/local/etc/v2ray/config.json"
        "/etc/x-ui/config.json"
        "/opt/3x-ui/bin/config.json"
        "/usr/local/x-ui/bin/config.json"
        "/opt/hiddify-manager/.env"
        "/etc/hysteria/config.json"
        "/etc/tuic/config.json"
        "/etc/trojan/config.json"
    )
    
    local config_ports=()
    
    for config_file in "${config_files[@]}"; do
        if [ -f "$config_file" ]; then
            debug_log "分析配置文件: $config_file"
            
            if [[ "$config_file" =~ \.json$ ]]; then
                # 简单的JSON端口提取，不依赖jq
                local ports=$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | grep -oE '[0-9]+' | sort -nu)
                if [ -n "$ports" ]; then
                    while read -r port; do
                        if ! is_internal_service_port "$port"; then
                            config_ports+=("$port")
                            debug_log "从 $config_file 解析端口: $port"
                        fi
                    done <<< "$ports"
                fi
            fi
        fi
    done
    
    if [ ${#config_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${config_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        debug_log "从配置文件解析到 ${#unique_ports[@]} 个端口"
    fi
}

# 检测监听端口
detect_listening_ports() {
    info "正在检测当前监听端口..."
    
    local listening_ports=()
    local localhost_ports=()
    
    while IFS= read -r line; do
        if [[ "$line" =~ LISTEN ]] || [[ "$line" =~ UNCONN ]]; then
            local protocol=$(echo "$line" | awk '{print tolower($1)}')
            local address_port=$(echo "$line" | awk '{print $5}')
            local process_info=$(echo "$line" | grep -oE 'users:\(\([^)]*\)\)' | head -1)
            
            local port=$(echo "$address_port" | grep -oE '[0-9]+$')
            
            local process="unknown"
            if [[ "$process_info" =~ \"([^\"]+)\" ]]; then
                process="${BASH_REMATCH[1]}"
            fi
            
            local bind_type=$(check_bind_address "$address_port")
            
            debug_log "检测到监听: $address_port ($protocol, $process, $bind_type)"
            
            if is_proxy_related "$process" && [ -n "$port" ] && [ "$port" != "$SSH_PORT" ]; then
                if [ "$bind_type" = "public" ]; then
                    if ! is_internal_service_port "$port"; then
                        listening_ports+=("$port")
                        debug_log "检测到公共代理端口: $port ($protocol, $process)"
                    else
                        debug_log "跳过内部服务端口: $port"
                    fi
                elif [ "$bind_type" = "localhost" ]; then
                    localhost_ports+=("$port")
                    debug_log "检测到本地代理端口: $port ($protocol, $process) - 不暴露"
                fi
            fi
        fi
    done <<< "$(ss -tulnp 2>/dev/null)"
    
    if [ ${#listening_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${listening_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        debug_log "检测到 ${#unique_ports[@]} 个公共监听端口"
    fi
}

# 检测 WARP 服务
detect_warp_service() {
    info "正在检测 Cloudflare WARP 服务..."
    
    local warp_found=false
    local warp_ports=()
    
    # 检测 WARP 进程
    if pgrep -f "warp" >/dev/null 2>&1; then
        warp_found=true
        debug_log "检测到 WARP 相关进程"
    fi
    
    # 检测标准 WireGuard/WARP 端口
    for warp_port in "${WARP_COMMON_PORTS[@]}"; do
        if ss -tulnp 2>/dev/null | grep -q ":$warp_port "; then
            warp_ports+=("$warp_port")
            debug_log "检测到标准 WARP 端口: $warp_port"
        fi
    done
    
    if [ "$warp_found" = true ] || [ ${#warp_ports[@]} -gt 0 ]; then
        debug_log "检测到 Cloudflare WARP 服务"
        
        if [ ${#warp_ports[@]} -gt 0 ]; then
            local unique_warp_ports=($(printf '%s\n' "${warp_ports[@]}" | sort -nu))
            DETECTED_PORTS+=("${unique_warp_ports[@]}")
        else
            # 添加常用 WARP 端口作为备用
            DETECTED_PORTS+=("${WARP_COMMON_PORTS[@]}")
        fi
        
        return 0
    else
        debug_log "未检测到 WARP 服务"
        return 1
    fi
}

# 检查进程是否为代理相关
is_proxy_related() {
    local process="$1"
    
    for proxy_proc in "${PROXY_CORE_PROCESSES[@]}" "${WEB_PANEL_PROCESSES[@]}"; do
        if [[ "$process" == *"$proxy_proc"* ]]; then
            return 0
        fi
    done
    
    if [[ "$process" =~ (proxy|vpn|tunnel|shadowsocks|trojan|v2ray|xray|clash|hysteria|sing|warp) ]]; then
        return 0
    fi
    
    return 1
}

# 检查端口是否为内部服务
is_internal_service_port() {
    local port="$1"
    
    for internal_port in "${INTERNAL_SERVICE_PORTS[@]}"; do
        if [ "$port" = "$internal_port" ]; then
            return 0
        fi
    fi
    
    return 1
}

# 检查端口是否为标准代理端口
is_standard_proxy_port() {
    local port="$1"
    
    local common_ports=(80 443 1080 1085 8080 8388 8443 8880 8888 9443)
    for common_port in "${common_ports[@]}"; do
        if [ "$port" = "$common_port" ]; then
            return 0
        fi
    done
    
    # 检查 WARP 常用端口
    for warp_port in "${WARP_COMMON_PORTS[@]}"; do
        if [ "$port" = "$warp_port" ]; then
            return 0
        fi
    done
    
    # 检查常用代理端口范围
    if [ "$port" -ge 30000 ] && [ "$port" -le 39999 ]; then
        return 0
    fi
    if [ "$port" -ge 40000 ] && [ "$port" -le 65000 ] && ! is_internal_service_port "$port"; then
        return 0
    fi
    
    return 1
}

# 端口安全检查
is_port_safe() {
    local port="$1"
    
    for blacklist_port in "${BLACKLIST_PORTS[@]}"; do
        if [ "$port" = "$blacklist_port" ]; then
            debug_log "端口 $port 在黑名单中"
            return 1
        fi
    done
    
    if is_internal_service_port "$port"; then
        debug_log "端口 $port 是内部服务端口"
        return 1
    fi
    
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        debug_log "端口 $port 超出有效范围"
        return 1
    fi
    
    return 0
}

# 分析和过滤端口
analyze_and_filter_ports() {
    info "正在分析和过滤端口..."
    
    # 添加默认开放端口
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    
    local all_ports=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    local safe_ports=()
    local suspicious_ports=()
    local unsafe_ports=()
    local internal_ports=()
    
    for port in "${all_ports[@]}"; do
        if ! is_port_safe "$port"; then
            if is_internal_service_port "$port"; then
                internal_ports+=("$port")
            else
                unsafe_ports+=("$port")
            fi
        elif is_standard_proxy_port "$port" || [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
            safe_ports+=("$port")
        else
            suspicious_ports+=("$port")
        fi
    done
    
    echo "端口分析结果:"
    echo "==================="
    
    if [ ${#safe_ports[@]} -gt 0 ]; then
        echo "安全端口 (将被开放):"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo "  ✓ $port (HTTP/HTTPS 标准端口)"
            elif [[ " ${WARP_COMMON_PORTS[*]} " =~ " $port " ]]; then
                echo "  ✓ $port (WARP 端口)"
            else
                echo "  ✓ $port (代理端口)"
            fi
        done
    fi
    
    if [ ${#internal_ports[@]} -gt 0 ]; then
        echo "内部服务端口 (已过滤):"
        for port in "${internal_ports[@]}"; do
            echo "  - $port (内部服务，不暴露)"
        done
    fi
    
    if [ ${#suspicious_ports[@]} -gt 0 ]; then
        echo "可疑端口 (需要确认):"
        for port in "${suspicious_ports[@]}"; do
            echo "  ? $port (非标准代理端口)"
        done
        
        if [ "$DRY_RUN" = false ]; then
            echo -e "${YELLOW}也要开放这些可疑端口吗？[y/N]${RESET}"
            read -r response
            if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
                safe_ports+=("${suspicious_ports[@]}")
                info "用户确认开放可疑端口"
            else
                info "跳过可疑端口"
            fi
        fi
    fi
    
    if [ ${#unsafe_ports[@]} -gt 0 ]; then
        echo "危险端口 (已跳过):"
        for port in "${unsafe_ports[@]}"; do
            echo "  ✗ $port (系统端口或危险端口)"
        done
    fi
    
    if [ ${#safe_ports[@]} -eq 0 ]; then
        warning "未检测到安全的代理端口，使用默认端口"
        safe_ports=("${DEFAULT_OPEN_PORTS[@]}")
    fi
    
    echo "即将开放 ${#safe_ports[@]} 个端口: ${safe_ports[*]}"
    
    if [ "$DRY_RUN" = false ]; then
        echo "是否继续? [Y/n]"
        read -r response
        if [[ ! "$response" =~ ^[Yy]?$ ]]; then
            info "用户取消操作"
            exit 0
        fi
    fi
    
    DETECTED_PORTS=($(printf '%s\n' "${safe_ports[@]}" | sort -nu))
    return 0
}

# 设置 nftables 基础结构
setup_nftables_base() {
    info "正在设置 nftables 基础结构..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将设置 nftables 基础结构"
        return 0
    fi
    
    # 创建主表
    nft add table inet "$NFTABLES_TABLE" 2>/dev/null || true
    
    # 创建链
    nft add chain inet "$NFTABLES_TABLE" input '{ type filter hook input priority 0; policy drop; }' 2>/dev/null || true
    nft add chain inet "$NFTABLES_TABLE" forward '{ type filter hook forward priority 0; policy drop; }' 2>/dev/null || true
    nft add chain inet "$NFTABLES_TABLE" output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true
    
    # 清空现有规则
    nft flush chain inet "$NFTABLES_TABLE" input 2>/dev/null || true
    nft flush chain inet "$NFTABLES_TABLE" forward 2>/dev/null || true
    nft flush chain inet "$NFTABLES_TABLE" output 2>/dev/null || true
    
    success "nftables 基础结构设置完成"
}

# 应用防火墙规则
apply_firewall_rules() {
    info "正在应用防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将应用防火墙规则"
        return 0
    fi
    
    # 设置基础结构
    setup_nftables_base
    
    info "添加基础规则..."
    # 基本规则：允许回环
    nft add rule inet "$NFTABLES_TABLE" input iif lo accept
    
    # 基本规则：允许已建立和相关连接
    nft add rule inet "$NFTABLES_TABLE" input ct state established,related accept
    
    # ICMP 支持（网络诊断）
    nft add rule inet "$NFTABLES_TABLE" input icmp type echo-request limit rate 10/second accept
    nft add rule inet "$NFTABLES_TABLE" input icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
    
    info "添加 SSH 保护规则..."
    # SSH 暴力破解防护规则
    nft add rule inet "$NFTABLES_TABLE" input tcp dport "$SSH_PORT" ct state new limit rate 4/minute accept
    
    info "开放代理端口..."
    # 开放代理端口（TCP 和 UDP）
    for port in "${DETECTED_PORTS[@]}"; do
        nft add rule inet "$NFTABLES_TABLE" input tcp dport "$port" accept
        nft add rule inet "$NFTABLES_TABLE" input udp dport "$port" accept
        debug_log "开放端口: $port (TCP/UDP)"
    done
    
    # 记录并丢弃其他连接（使用英文前缀避免语法错误）
    nft add rule inet "$NFTABLES_TABLE" input limit rate 3/minute log prefix "firewall-drop: " level info
    
    OPENED_PORTS=${#DETECTED_PORTS[@]}
    success "防火墙规则应用成功"
    
    # 保存规则
    save_nftables_rules
}

# 保存 nftables 规则
save_nftables_rules() {
    info "正在保存防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将保存防火墙规则"
        return 0
    fi
    
    local config_file="/etc/nftables.conf"
    
    # 保存当前规则集
    nft list table inet "$NFTABLES_TABLE" > "$config_file" 2>/dev/null || {
        warning "无法保存到 $config_file"
        config_file="/tmp/nftables_rules.nft"
        nft list table inet "$NFTABLES_TABLE" > "$config_file"
    }
    
    # 创建服务文件以确保规则持久化
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable nftables >/dev/null 2>&1 || true
    fi
    
    success "防火墙规则已保存"
}

# 交互式端口范围添加
add_port_range_interactive() {
    echo "配置端口转发规则"
    echo "端口转发允许将端口范围重定向到单个目标端口"
    echo "示例: 16820-16888 转发到 16801"
    
    while true; do
        echo
        echo "请输入端口范围（格式: 起始-结束，如 16820-16888）:"
        read -r port_range
        
        if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start_port="${BASH_REMATCH[1]}"
            local end_port="${BASH_REMATCH[2]}"
            
            if [ "$start_port" -ge "$end_port" ]; then
                echo "起始端口必须小于结束端口"
                continue
            fi
            
            echo "请输入目标端口（单个端口号）:"
            read -r target_port
            
            if [[ "$target_port" =~ ^[0-9]+$ ]] && [ "$target_port" -ge 1 ] && [ "$target_port" -le 65535 ]; then
                NAT_RULES+=("$port_range->$target_port")
                DETECTED_PORTS+=("$target_port")
                success "添加端口转发规则: $port_range -> $target_port"
                
                echo "继续添加其他端口转发规则吗？[y/N]"
                read -r response
                if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
                    break
                fi
            else
                echo "无效的目标端口: $target_port"
            fi
        else
            echo "无效的端口范围格式: $port_range"
        fi
    done
}

# 手动添加单个端口
add_single_port_interactive() {
    echo "手动添加端口"
    echo "允许添加单个端口或多个端口（用逗号分隔）"
    echo "示例: 8080 或 8080,8081,8082"
    
    while true; do
        echo
        echo "请输入要添加的端口（单个或用逗号分隔的多个）:"
        read -r input_ports
        
        if [ -z "$input_ports" ]; then
            echo "端口不能为空"
            continue
        fi
        
        # 分割端口
        IFS=',' read -ra ports <<< "$input_ports"
        local valid_ports=()
        local invalid_ports=()
        
        for port in "${ports[@]}"; do
            # 去除空格
            port=$(echo "$port" | tr -d ' ')
            
            if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
                if is_port_safe "$port"; then
                    valid_ports+=("$port")
                else
                    invalid_ports+=("$port")
                fi
            else
                invalid_ports+=("$port")
            fi
        done
        
        if [ ${#invalid_ports[@]} -gt 0 ]; then
            echo "无效或危险的端口: ${invalid_ports[*]}"
            echo "继续添加有效端口吗？[y/N]"
            read -r response
            if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
                continue
            fi
        fi
        
        if [ ${#valid_ports[@]} -gt 0 ]; then
            echo
            echo "将添加以下端口:"
            for port in "${valid_ports[@]}"; do
                echo "  • $port"
            done
            
            echo
            echo "确认添加这些端口吗？[Y/n]"
            read -r response
            if [[ "$response" =~ ^[Yy]?$ ]]; then
                for port in "${valid_ports[@]}"; do
                    DETECTED_PORTS+=("$port")
                    success "添加端口: $port"
                done
                
                success "已添加 ${#valid_ports[@]} 个端口"
            fi
        else
            echo "没有有效的端口可添加"
        fi
        
        echo
        echo "继续添加其他端口吗？[y/N]"
        read -r response
        if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            break
        fi
    done
}

# 重置防火墙
reset_firewall() {
    echo "重置防火墙到默认状态"
    
    if [ "$DRY_RUN" = false ]; then
        echo "警告: 这将清除所有 nftables 规则！"
        echo "确认重置防火墙吗？[y/N]"
        read -r response
        if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            info "重置操作已取消"
            return 0
        fi
    fi
    
    info "重置 nftables 规则..."
    
    if [ "$DRY_RUN" = false ]; then
        # 删除代理防火墙表
        if nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
            nft delete table inet "$NFTABLES_TABLE" 2>/dev/null || true
        fi
        
        # 清除所有规则集（谨慎操作）
        echo "是否要清除所有 nftables 规则？这可能影响其他服务 [y/N]"
        read -r response
        if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            nft flush ruleset
        fi
        
        success "防火墙已重置到默认状态"
    else
        info "[预览模式] 将重置所有 nftables 规则"
    fi
}

# 显示防火墙状态
show_firewall_status() {
    echo "当前防火墙状态"
    echo
    
    if ! nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
        echo "代理防火墙表不存在"
        echo "当前所有 nftables 表:"
        nft list tables 2>/dev/null || echo "无表"
        return 0
    fi
    
    echo "nftables 规则统计:"
    local input_rules=$(nft list chain inet "$NFTABLES_TABLE" input 2>/dev/null | grep -c "accept\|drop\|log" || echo "0")
    echo "  INPUT 规则数: $input_rules"
    echo
    
    echo "开放的端口:"
    nft list chain inet "$NFTABLES_TABLE" input 2>/dev/null | grep "dport.*accept" | while read -r line; do
        if echo "$line" | grep -qE "tcp dport [0-9]+"; then
            local port=$(echo "$line" | grep -oE "dport [0-9]+" | awk '{print $2}')
            echo "  • $port (tcp)"
        elif echo "$line" | grep -qE "udp dport [0-9]+"; then
            local port=$(echo "$line" | grep -oE "dport [0-9]+" | awk '{print $2}')
            echo "  • $port (udp)"
        fi
    done
    echo
    
    echo "SSH 保护状态:"
    if nft list chain inet "$NFTABLES_TABLE" input 2>/dev/null | grep -q "limit"; then
        echo "  SSH 暴力破解防护已启用"
    else
        echo "  SSH 暴力破解防护未启用"
    fi
    echo
    
    echo "管理命令:"
    echo "  查看所有规则: nft list ruleset"
    echo "  查看代理表: nft list table inet $NFTABLES_TABLE"
    echo "  查看监听端口: ss -tlnp"
    echo "  重新配置: bash \$0"
    echo "  重置防火墙: bash \$0 --reset"
}

# 显示最终状态
show_final_status() {
    echo
    echo "=========================================="
    echo "防火墙配置完成！"
    echo "=========================================="
    
    echo
    echo "配置摘要:"
    echo "  开放端口数: $OPENED_PORTS"
    echo "  SSH 端口: $SSH_PORT (已保护)"
    echo "  防火墙引擎: nftables"
    echo "  防火墙表: $NFTABLES_TABLE"
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo
        echo "已开放端口:"
        for port in "${DETECTED_PORTS[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo "  • $port (TCP/UDP) - 默认开放"
            elif [[ " ${WARP_COMMON_PORTS[*]} " =~ " $port " ]]; then
                echo "  • $port (TCP/UDP) - WARP 端口"
            else
                echo "  • $port (TCP/UDP)"
            fi
        done
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo
        echo "这是预览模式，防火墙实际未被修改"
        return 0
    fi
    
    echo
    echo "管理命令:"
    echo "  查看所有规则: nft list ruleset"
    echo "  查看代理表: nft list table inet $NFTABLES_TABLE"
    echo "  查看监听端口: ss -tlnp"
    echo "  查看状态: bash \$0 --status"
    echo "  手动添加端口: bash \$0 --add-port"
    echo "  重置防火墙: bash \$0 --reset"
    
    echo
    echo "代理端口已精确开放，内部服务受保护，服务器安全已启用！"
    
    # 显示 nftables 服务状态
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-enabled nftables >/dev/null 2>&1; then
            echo
            echo "nftables 服务已启用，规则将在重启后自动恢复"
        else
            echo
            echo "建议启用 nftables 服务以确保规则持久化:"
            echo "  systemctl enable nftables"
        fi
    fi
}

# 主函数
main() {
    trap 'echo -e "\n操作被中断"; exit 130' INT TERM
    
    parse_arguments "$@"
    
    echo "开始智能代理端口检测和防火墙配置..."
    
    check_system
    detect_ssh_port
    
    # 每次运行前清理旧规则
    cleanup_existing_rules
    
    # 检测代理服务
    if ! detect_proxy_processes; then
        warning "建议在运行此脚本之前启动代理服务以获得最佳效果"
    fi
    
    # 解析配置和检测端口
    parse_config_ports
    detect_listening_ports
    detect_warp_service
    
    # 分析和过滤端口
    if ! analyze_and_filter_ports; then
        error_exit "无法确定要开放的端口"
    fi
    
    # 应用防火墙规则
    apply_firewall_rules
    show_final_status
}

# 脚本入口点
main "$@"

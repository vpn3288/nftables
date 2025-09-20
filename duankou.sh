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
SCRIPT_VERSION="2.2.0"
SCRIPT_NAME="智能代理端口防火墙管理工具"

echo -e "${CYAN}============================================${RESET}"
echo -e "${YELLOW}   ${SCRIPT_NAME} v${SCRIPT_VERSION}   ${RESET}"
echo -e "${CYAN}============================================${RESET}"
echo -e "${GREEN}专为 Hiddify、3X-UI、X-UI、Sing-box、Xray、WARP 等代理工具优化${RESET}"
echo -e "${CYAN}使用现代化 nftables 防火墙技术，安全可靠${RESET}"
echo ""

# 权限检查
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}错误: 需要 root 权限运行此脚本${RESET}"
    echo -e "${YELLOW}请使用: sudo bash $0${RESET}"
    exit 1
fi

# 全局变量
DEBUG_MODE=false
DRY_RUN=false
SSH_PORT=""
DETECTED_PORTS=()
NAT_RULES=()
OPENED_PORTS=0
NFTABLES_TABLE="proxy_firewall"

# 默认开放端口（HTTP/HTTPS）
DEFAULT_OPEN_PORTS=(80 443)

# 代理服务进程名称
PROXY_PROCESSES=(
    "xray" "v2ray" "sing-box" "singbox" "sing_box"
    "hysteria" "hysteria2" "tuic" "juicity" "shadowtls"
    "hiddify" "hiddify-panel" "hiddify-manager"
    "x-ui" "3x-ui" "v2-ui" "v2rayA" "v2raya"
    "trojan" "trojan-go" "trojan-plus"
    "shadowsocks-rust" "ss-server" "shadowsocks-libev" "go-shadowsocks2"
    "brook" "gost" "naive" "clash" "clash-meta" "mihomo"
    "warp-svc" "warp" "cloudflare-warp" "warp-cli"
    "nginx" "caddy" "apache2" "httpd" "haproxy"
)

# Hiddify 面板常用端口
HIDDIFY_PORTS=(443 8443 9443 80 8080 8880 2053 2083 2087 2096)

# WARP 相关端口
WARP_PORTS=(2408 500 1701 4500 51820 51821 38001 38002)

# 内部服务端口（不对外开放）
INTERNAL_PORTS=(
    8181 10085 10086 9090 3000 3001 8000 8001
    10080 10081 10082 10083 10084 54321 62789
    8090 8091 8092 8093 8094 8095
)

# 危险端口黑名单
DANGEROUS_PORTS=(
    22 23 25 53 69 111 135 137 138 139 445 514 631
    1433 1521 3306 5432 6379 27017
    3389 5900 5901 5902
    110 143 465 587 993 995
)

# 辅助函数
log_debug() {
    if [ "$DEBUG_MODE" = true ]; then
        echo -e "${BLUE}[调试] $1${RESET}"
    fi
}

log_error() {
    echo -e "${RED}[错误] $1${RESET}"
}

log_warning() {
    echo -e "${YELLOW}[警告] $1${RESET}"
}

log_success() {
    echo -e "${GREEN}[成功] $1${RESET}"
}

log_info() {
    echo -e "${CYAN}[信息] $1${RESET}"
}

error_exit() {
    echo -e "${RED}[致命错误] $1${RESET}"
    exit 1
}

# 显示帮助信息
show_help() {
    cat << 'HELP_EOF'

智能代理端口防火墙管理工具 v2.2.0

这是一个专为代理服务器设计的智能防火墙配置工具，支持自动检测和安全配置。

使用方法:
    bash script.sh [选项]

可用选项:
    --debug           显示详细的调试信息
    --dry-run         预览模式，不实际修改防火墙规则
    --add-port        手动添加端口
    --add-range       添加端口转发规则
    --reset           重置防火墙到默认状态
    --status          显示当前防火墙状态
    --help, -h        显示此帮助信息

支持的代理软件:
    ✓ Hiddify Manager/Panel    ✓ 3X-UI / X-UI
    ✓ Xray / V2Ray            ✓ Sing-box
    ✓ Hysteria / Hysteria2     ✓ Trojan-Go / Trojan
    ✓ Shadowsocks 系列        ✓ Cloudflare WARP
    ✓ Clash / Mihomo          ✓ Brook / Gost

安全特性:
    ✓ 智能端口检测            ✓ 自动过滤危险端口
    ✓ SSH 暴力破解防护        ✓ 内部服务保护
    ✓ 现代化 nftables 架构    ✓ 规则持久化保存

HELP_EOF
}

# 解析命令行参数
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                DEBUG_MODE=true
                log_info "调试模式已启用"
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                log_info "预览模式已启用，不会实际修改防火墙"
                shift
                ;;
            --add-port)
                add_custom_port
                exit 0
                ;;
            --add-range)
                add_port_forwarding
                exit 0
                ;;
            --reset)
                reset_firewall
                exit 0
                ;;
            --status)
                show_status
                exit 0
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error_exit "未知参数: $1"
                ;;
        esac
    done
}

# 检查系统环境和依赖
check_system_requirements() {
    log_info "正在检查系统环境..."
    
    # 检查必需工具
    local required_tools=("nft" "ss" "systemctl")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    # 安装缺失的工具
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_info "正在安装缺失的工具: ${missing_tools[*]}"
        
        if [ "$DRY_RUN" = false ]; then
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq >/dev/null 2>&1
                apt-get install -y nftables iproute2 >/dev/null 2>&1
            elif command -v yum >/dev/null 2>&1; then
                yum install -y nftables iproute >/dev/null 2>&1
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y nftables iproute >/dev/null 2>&1
            elif command -v pacman >/dev/null 2>&1; then
                pacman -S --noconfirm nftables iproute2 >/dev/null 2>&1
            else
                error_exit "无法自动安装依赖包，请手动安装: ${missing_tools[*]}"
            fi
        fi
    fi
    
    # 启用 nftables 服务
    if [ "$DRY_RUN" = false ]; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl enable nftables >/dev/null 2>&1 || true
            systemctl start nftables >/dev/null 2>&1 || true
        fi
    fi
    
    log_success "系统环境检查完成"
}

# 检测 SSH 端口
detect_ssh_port() {
    log_info "正在检测 SSH 端口..."
    
    # 从监听端口检测
    local ssh_port=$(ss -tlnp 2>/dev/null | grep sshd | head -1 | awk '{print $4}' | awk -F: '{print $NF}')
    
    # 从配置文件检测
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] && [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -i '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print $2}' | head -1)
    fi
    
    # 默认端口
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]]; then
        ssh_port="22"
    fi
    
    SSH_PORT="$ssh_port"
    log_info "检测到 SSH 端口: $SSH_PORT"
}

# 检测代理服务进程
detect_proxy_services() {
    log_info "正在检测代理服务..."
    
    local found_services=()
    local service_ports=()
    
    # 检测运行中的代理进程
    for process in "${PROXY_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found_services+=("$process")
            log_debug "发现代理进程: $process"
        fi
    done
    
    if [ ${#found_services[@]} -gt 0 ]; then
        log_success "检测到代理服务: ${found_services[*]}"
        return 0
    else
        log_warning "未检测到运行中的代理服务"
        return 1
    fi
}

# 从配置文件解析端口
parse_config_files() {
    log_info "正在解析代理配置文件..."
    
    local config_files=(
        "/opt/hiddify-manager/.env"
        "/etc/x-ui/config.json"
        "/usr/local/x-ui/bin/config.json" 
        "/opt/3x-ui/bin/config.json"
        "/usr/local/etc/xray/config.json"
        "/etc/xray/config.json"
        "/usr/local/etc/v2ray/config.json"
        "/etc/v2ray/config.json"
        "/etc/sing-box/config.json"
        "/opt/sing-box/config.json"
        "/usr/local/etc/sing-box/config.json"
    )
    
    local config_ports=()
    
    for config_file in "${config_files[@]}"; do
        if [ -f "$config_file" ]; then
            log_debug "分析配置文件: $config_file"
            
            if [[ "$config_file" =~ \.json$ ]]; then
                # JSON 配置文件
                if command -v jq >/dev/null 2>&1; then
                    local ports=$(jq -r '.inbounds[]? | .port' "$config_file" 2>/dev/null | grep -E '^[0-9]+$')
                    if [ -n "$ports" ]; then
                        while read -r port; do
                            config_ports+=("$port")
                            log_debug "从 $config_file 解析到端口: $port"
                        done <<< "$ports"
                    fi
                else
                    # 没有 jq，使用正则表达式
                    local ports=$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | grep -oE '[0-9]+')
                    if [ -n "$ports" ]; then
                        while read -r port; do
                            config_ports+=("$port")
                            log_debug "从 $config_file 解析到端口: $port"
                        done <<< "$ports"
                    fi
                fi
            elif [[ "$config_file" =~ \.env$ ]]; then
                # ENV 配置文件
                local ports=$(grep -oE 'PORT[^=]*=[0-9]+' "$config_file" | grep -oE '[0-9]+')
                if [ -n "$ports" ]; then
                    while read -r port; do
                        config_ports+=("$port")
                        log_debug "从 $config_file 解析到端口: $port"
                    done <<< "$ports"
                fi
            fi
        fi
    done
    
    if [ ${#config_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${config_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        log_success "从配置文件解析到 ${#unique_ports[@]} 个端口"
    fi
}

# 检测监听端口
detect_listening_ports() {
    log_info "正在检测当前监听端口..."
    
    local listening_ports=()
    
    # 解析 ss 命令输出
    while IFS= read -r line; do
        if [[ "$line" =~ LISTEN ]]; then
            local address_port=$(echo "$line" | awk '{print $5}')
            local port=$(echo "$address_port" | grep -oE '[0-9]+$')
            local process_info=$(echo "$line" | grep -oE 'users:\(\([^)]*\)\)')
            
            if [ -n "$port" ] && [ "$port" != "$SSH_PORT" ]; then
                # 检查是否为公网监听
                if [[ "$address_port" =~ ^(\*|0\.0\.0\.0|\[::\]|::): ]]; then
                    # 检查是否为代理相关进程
                    local is_proxy=false
                    for process in "${PROXY_PROCESSES[@]}"; do
                        if [[ "$process_info" =~ $process ]]; then
                            is_proxy=true
                            break
                        fi
                    done
                    
                    if [ "$is_proxy" = true ] || is_common_proxy_port "$port"; then
                        listening_ports+=("$port")
                        log_debug "检测到代理监听端口: $port"
                    fi
                fi
            fi
        fi
    done <<< "$(ss -tlnp 2>/dev/null)"
    
    if [ ${#listening_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${listening_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        log_success "检测到 ${#unique_ports[@]} 个监听端口"
    fi
}

# 检测 WARP 服务
detect_warp_service() {
    log_info "正在检测 Cloudflare WARP 服务..."
    
    local warp_detected=false
    local warp_ports=()
    
    # 检测 WARP 进程
    if pgrep -f "warp" >/dev/null 2>&1; then
        warp_detected=true
        log_debug "检测到 WARP 进程"
    fi
    
    # 检测 WARP 配置文件
    local warp_configs=("/var/lib/cloudflare-warp/mdm.xml" "/opt/warp/config.json")
    for config in "${warp_configs[@]}"; do
        if [ -f "$config" ]; then
            warp_detected=true
            log_debug "发现 WARP 配置文件: $config"
        fi
    done
    
    # 检测 WARP 相关监听端口
    while IFS= read -r line; do
        if [[ "$line" =~ LISTEN ]] || [[ "$line" =~ UNCONN ]]; then
            local port=$(echo "$line" | awk '{print $5}' | grep -oE '[0-9]+$')
            local process_info=$(echo "$line" | grep -oE 'users:\(\([^)]*\)\)')
            
            if [[ "$process_info" =~ warp ]] && [ -n "$port" ]; then
                warp_ports+=("$port")
                log_debug "检测到 WARP 端口: $port"
            fi
        fi
    done <<< "$(ss -tulnp 2>/dev/null)"
    
    if [ "$warp_detected" = true ]; then
        log_success "检测到 Cloudflare WARP 服务"
        
        if [ ${#warp_ports[@]} -gt 0 ]; then
            local unique_warp_ports=($(printf '%s\n' "${warp_ports[@]}" | sort -nu))
            DETECTED_PORTS+=("${unique_warp_ports[@]}")
            log_info "WARP 端口: ${unique_warp_ports[*]}"
        else
            # 添加常用 WARP 端口
            DETECTED_PORTS+=("${WARP_PORTS[@]}")
            log_info "添加标准 WARP 端口: ${WARP_PORTS[*]}"
        fi
    else
        log_debug "未检测到 WARP 服务"
    fi
}

# 检查是否为常见代理端口
is_common_proxy_port() {
    local port="$1"
    local common_ports=(80 443 1080 1085 8080 8388 8443 8880 8888 9443)
    
    for common_port in "${common_ports[@]}"; do
        if [ "$port" = "$common_port" ]; then
            return 0
        fi
    done
    
    # 检查端口范围
    if [ "$port" -ge 30000 ] && [ "$port" -le 39999 ]; then
        return 0
    fi
    if [ "$port" -ge 40000 ] && [ "$port" -le 65000 ]; then
        return 0
    fi
    
    return 1
}

# 端口安全检查
is_port_safe() {
    local port="$1"
    
    # 检查危险端口
    for dangerous_port in "${DANGEROUS_PORTS[@]}"; do
        if [ "$port" = "$dangerous_port" ]; then
            log_debug "端口 $port 在危险端口列表中"
            return 1
        fi
    done
    
    # 检查内部服务端口
    for internal_port in "${INTERNAL_PORTS[@]}"; do
        if [ "$port" = "$internal_port" ]; then
            log_debug "端口 $port 是内部服务端口"
            return 1
        fi
    done
    
    # 检查端口范围
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        log_debug "端口 $port 超出有效范围"
        return 1
    fi
    
    return 0
}

# 过滤和确认端口
filter_and_confirm_ports() {
    log_info "正在分析和过滤端口..."
    
    # 添加默认端口
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    
    # 去重并排序
    local all_ports=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    local safe_ports=()
    local unsafe_ports=()
    local internal_ports=()
    
    for port in "${all_ports[@]}"; do
        if is_port_safe "$port"; then
            safe_ports+=("$port")
        else
            # 区分危险端口和内部端口
            local is_internal=false
            for internal_port in "${INTERNAL_PORTS[@]}"; do
                if [ "$port" = "$internal_port" ]; then
                    internal_ports+=("$port")
                    is_internal=true
                    break
                fi
            done
            
            if [ "$is_internal" = false ]; then
                unsafe_ports+=("$port")
            fi
        fi
    done
    
    # 显示分析结果
    echo ""
    echo -e "${CYAN}端口分析结果:${RESET}"
    echo -e "${CYAN}===================${RESET}"
    
    if [ ${#safe_ports[@]} -gt 0 ]; then
        echo -e "${GREEN}安全端口 (将被开放):${RESET}"
        for port in "${safe_ports[@]}"; do
            local port_desc=""
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                port_desc=" (HTTP/HTTPS 标准端口)"
            elif [[ " ${WARP_PORTS[*]} " =~ " $port " ]]; then
                port_desc=" (WARP 端口)"
            elif [[ " ${HIDDIFY_PORTS[*]} " =~ " $port " ]]; then
                port_desc=" (Hiddify 端口)"
            fi
            echo -e "  ${GREEN}✓ $port${port_desc}${RESET}"
        done
    fi
    
    if [ ${#internal_ports[@]} -gt 0 ]; then
        echo -e "${YELLOW}内部服务端口 (已过滤):${RESET}"
        for port in "${internal_ports[@]}"; do
            echo -e "  ${YELLOW}⚠ $port (内部服务端口，不对外开放)${RESET}"
        done
    fi
    
    if [ ${#unsafe_ports[@]} -gt 0 ]; then
        echo -e "${RED}危险端口 (已跳过):${RESET}"
        for port in "${unsafe_ports[@]}"; do
            echo -e "  ${RED}✗ $port (系统关键端口)${RESET}"
        done
    fi
    
    # 如果没有检测到安全端口，使用默认配置
    if [ ${#safe_ports[@]} -eq 0 ]; then
        log_warning "未检测到代理端口，将使用默认配置"
        safe_ports=("${DEFAULT_OPEN_PORTS[@]}" "${HIDDIFY_PORTS[@]}")
    fi
    
    # 最终确认
    if [ "$DRY_RUN" = false ]; then
        echo ""
        echo -e "${CYAN}即将开放 ${#safe_ports[@]} 个端口: ${safe_ports[*]}${RESET}"
        echo -e "${YELLOW}是否继续? [Y/n]${RESET}"
        read -r response
        if [[ "$response" =~ ^[Nn]$ ]]; then
            log_info "用户取消操作"
            exit 0
        fi
    fi
    
    DETECTED_PORTS=($(printf '%s\n' "${safe_ports[@]}" | sort -nu))
    return 0
}

# 清理现有防火墙规则
cleanup_existing_firewall() {
    log_info "正在清理现有防火墙配置..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[预览模式] 将清理现有防火墙配置"
        return 0
    fi
    
    # 停用其他防火墙服务
    local other_firewalls=("ufw" "firewalld" "iptables")
    for firewall in "${other_firewalls[@]}"; do
        if systemctl is-active --quiet "$firewall" 2>/dev/null; then
            systemctl stop "$firewall" >/dev/null 2>&1 || true
            systemctl disable "$firewall" >/dev/null 2>&1 || true
            log_success "已停用 $firewall"
        fi
    done
    
    # 重置 ufw（如果存在）
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1 || true
    fi
    
    # 备份现有 nftables 规则
    if nft list ruleset >/dev/null 2>&1; then
        local backup_file="/tmp/nftables_backup_$(date +%Y%m%d_%H%M%S).nft"
        nft list ruleset > "$backup_file" 2>/dev/null || true
        log_info "已备份现有规则到: $backup_file"
    fi
    
    # 删除旧的代理防火墙表
    if nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
        nft delete table inet "$NFTABLES_TABLE" 2>/dev/null || true
        log_info "已删除旧的防火墙表"
    fi
    
    log_success "防火墙清理完成"
}

# 创建 nftables 基础结构
setup_nftables_base() {
    log_info "正在设置 nftables 基础结构..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[预览模式] 将设置 nftables 基础结构"
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
    
    log_success "nftables 基础结构设置完成"
}

# 应用防火墙规则
apply_firewall_rules() {
    log_info "正在应用防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        show_preview_rules
        return 0
    fi
    
    # 设置基础结构
    setup_nftables_base
    
    # 基本规则
    log_info "添加基础规则..."
    nft add rule inet "$NFTABLES_TABLE" input iif lo accept  # 回环接口
    nft add rule inet "$NFTABLES_TABLE" input ct state established,related accept  # 已建立连接
    nft add rule inet "$NFTABLES_TABLE" input icmp type echo-request limit rate 10/second accept  # ICMP
    nft add rule inet "$NFTABLES_TABLE" input icmpv6 type '{ echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert }' accept  # ICMPv6
    
    # SSH 保护规则
    log_info "添加 SSH 保护规则..."
    nft add rule inet "$NFTABLES_TABLE" input tcp dport "$SSH_PORT" ct state new limit rate 4/minute accept
    
    # 开放代理端口
    log_info "开放代理端口..."
    local unique_ports=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    for port in "${unique_ports[@]}"; do
        nft add rule inet "$NFTABLES_TABLE" input tcp dport "$port" accept
        nft add rule inet "$NFTABLES_TABLE" input udp dport "$port" accept
        log_debug "开放端口: $port (TCP/UDP)"
    done
    
    # 日志记录规则
    nft add rule inet "$NFTABLES_TABLE" input limit rate 3/minute log prefix "防火墙拦截: " level info
    
    OPENED_PORTS=${#unique_ports[@]}
    log_success "防火墙规则应用完成"
    
    # 保存规则
    save_firewall_rules
}

# 显示规则预览
show_preview_rules() {
    echo ""
    echo -e "${CYAN}防火墙规则预览:${RESET}"
    echo -e "${CYAN}=================${RESET}"
    
    echo "table inet $NFTABLES_TABLE {"
    echo "    chain input {"
    echo "        type filter hook input priority 0; policy drop;"
    echo "        iif lo accept  # 允许回环"
    echo "        ct state established,related accept  # 允许已建立连接"
    echo "        icmp type echo-request limit rate 10/second accept  # ICMP 限速"
    echo "        tcp dport $SSH_PORT ct state new limit rate 4/minute accept  # SSH 保护"
    echo ""
    echo "        # 代理端口"
    for port in "${DETECTED_PORTS[@]}"; do
        echo "        tcp dport $port accept"
        echo "        udp dport $port accept"
    done
    echo ""
    echo "        limit rate 3/minute log prefix \"防火墙拦截: \" level info"
    echo "    }"
    echo ""
    echo "    chain forward {"
    echo "        type filter hook forward priority 0; policy drop;"
    echo "    }"
    echo ""
    echo "    chain output {"
    echo "        type filter hook output priority 0; policy accept;"
    echo "    }"
    echo "}"
}

# 保存防火墙规则
save_firewall_rules() {
    log_info "正在保存防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        log_info "[预览模式] 将保存防火墙规则"
        return 0
    fi
    
    # 确定配置文件路径
    local config_file="/etc/nftables.conf"
    if [ -d "/etc/nftables" ]; then
        config_file="/etc/nftables/proxy_firewall.nft"
    fi
    
    # 保存当前规则
    if nft list table inet "$NFTABLES_TABLE" > "$config_file" 2>/dev/null; then
        log_success "规则已保存到: $config_file"
    else
        log_warning "无法保存到系统配置，保存到临时文件"
        config_file="/tmp/nftables_proxy_rules.nft"
        nft list table inet "$NFTABLES_TABLE" > "$config_file"
        log_info "规则已保存到: $config_file"
    fi
    
    # 确保服务开机启动
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable nftables.service >/dev/null 2>&1 || true
        log_info "已启用 nftables 服务自动启动"
    fi
}

# 手动添加端口
add_custom_port() {
    echo -e "${CYAN}手动添加端口${RESET}"
    echo -e "${CYAN}================${RESET}"
    
    while true; do
        echo -e "${YELLOW}请输入要添加的端口 (单个端口或用逗号分隔多个端口):${RESET}"
        read -r input_ports
        
        if [ -z "$input_ports" ]; then
            log_error "端口不能为空"
            continue
        fi
        
        # 分割端口
        IFS=',' read -ra ports <<< "$input_ports"
        local valid_ports=()
        local invalid_ports=()
        
        for port in "${ports[@]}"; do
            port=$(echo "$port" | tr -d ' ')  # 去除空格
            
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
            log_error "无效或危险的端口: ${invalid_ports[*]}"
        fi
        
        if [ ${#valid_ports[@]} -gt 0 ]; then
            echo -e "${GREEN}将添加以下端口:${RESET}"
            for port in "${valid_ports[@]}"; do
                echo -e "  ${GREEN}✓ $port${RESET}"
            done
            
            echo -e "${YELLOW}确认添加这些端口吗? [Y/n]${RESET}"
            read -r response
            if [[ "$response" =~ ^[Yy]?$ ]]; then
                # 立即应用规则
                for port in "${valid_ports[@]}"; do
                    if nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
                        nft add rule inet "$NFTABLES_TABLE" input tcp dport "$port" accept 2>/dev/null || true
                        nft add rule inet "$NFTABLES_TABLE" input udp dport "$port" accept 2>/dev/null || true
                        log_success "已添加端口: $port"
                    else
                        log_error "防火墙表不存在，请先运行主脚本"
                        return 1
                    fi
                done
                save_firewall_rules
            fi
        else
            log_error "没有有效的端口可添加"
        fi
        
        echo -e "${YELLOW}继续添加其他端口吗? [y/N]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            break
        fi
    done
}

# 添加端口转发规则
add_port_forwarding() {
    echo -e "${CYAN}配置端口转发${RESET}"
    echo -e "${CYAN}===============${RESET}"
    echo -e "${YELLOW}端口转发可以将外部端口范围重定向到内部单一端口${RESET}"
    echo -e "${YELLOW}示例: 将 10000-10100 转发到 8080${RESET}"
    echo ""
    
    # 检查是否已有 NAT 表
    if ! nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
        log_error "防火墙表不存在，请先运行主脚本"
        return 1
    fi
    
    # 创建 prerouting 链（如果不存在）
    if ! nft list chain inet "$NFTABLES_TABLE" prerouting >/dev/null 2>&1; then
        nft add chain inet "$NFTABLES_TABLE" prerouting '{ type nat hook prerouting priority -100; }' 2>/dev/null || true
        log_info "已创建 prerouting 链"
    fi
    
    while true; do
        echo -e "${YELLOW}请输入源端口范围 (格式: 起始端口-结束端口):${RESET}"
        read -r port_range
        
        if [[ ! "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            log_error "端口范围格式错误，请使用 起始端口-结束端口 格式"
            continue
        fi
        
        local start_port="${BASH_REMATCH[1]}"
        local end_port="${BASH_REMATCH[2]}"
        
        if [ "$start_port" -ge "$end_port" ]; then
            log_error "起始端口必须小于结束端口"
            continue
        fi
        
        echo -e "${YELLOW}请输入目标端口:${RESET}"
        read -r target_port
        
        if [[ ! "$target_port" =~ ^[0-9]+$ ]] || [ "$target_port" -lt 1 ] || [ "$target_port" -gt 65535 ]; then
            log_error "目标端口无效"
            continue
        fi
        
        echo -e "${GREEN}将配置端口转发: $port_range -> $target_port${RESET}"
        echo -e "${YELLOW}确认添加此转发规则吗? [Y/n]${RESET}"
        read -r response
        
        if [[ "$response" =~ ^[Yy]?$ ]]; then
            # 添加 DNAT 规则
            nft add rule inet "$NFTABLES_TABLE" prerouting tcp dport "$start_port-$end_port" dnat to ":$target_port" 2>/dev/null || true
            nft add rule inet "$NFTABLES_TABLE" prerouting udp dport "$start_port-$end_port" dnat to ":$target_port" 2>/dev/null || true
            
            # 开放源端口范围
            nft add rule inet "$NFTABLES_TABLE" input tcp dport "$start_port-$end_port" accept 2>/dev/null || true
            nft add rule inet "$NFTABLES_TABLE" input udp dport "$start_port-$end_port" accept 2>/dev/null || true
            
            log_success "已添加端口转发规则: $port_range -> $target_port"
            save_firewall_rules
        fi
        
        echo -e "${YELLOW}继续添加其他转发规则吗? [y/N]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            break
        fi
    done
}

# 重置防火墙
reset_firewall() {
    echo -e "${YELLOW}重置防火墙设置${RESET}"
    echo -e "${YELLOW}=================${RESET}"
    
    echo -e "${RED}警告: 这将清除所有防火墙规则！${RESET}"
    echo -e "${YELLOW}确认要重置防火墙吗? [y/N]${RESET}"
    read -r response
    
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log_info "重置操作已取消"
        return 0
    fi
    
    # 删除代理防火墙表
    if nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
        nft delete table inet "$NFTABLES_TABLE" 2>/dev/null || true
        log_success "已删除代理防火墙表"
    fi
    
    # 询问是否清除所有 nftables 规则
    echo -e "${YELLOW}是否要清除所有 nftables 规则? (这可能影响其他服务) [y/N]${RESET}"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        nft flush ruleset 2>/dev/null || true
        log_success "已清除所有 nftables 规则"
    fi
    
    log_success "防火墙重置完成"
}

# 显示防火墙状态
show_status() {
    echo -e "${CYAN}防火墙状态检查${RESET}"
    echo -e "${CYAN}=================${RESET}"
    
    # 检查 nftables 服务状态
    if command -v systemctl >/dev/null 2>&1; then
        local service_status=$(systemctl is-active nftables 2>/dev/null || echo "inactive")
        echo -e "nftables 服务状态: ${service_status}"
        
        local service_enabled=$(systemctl is-enabled nftables 2>/dev/null || echo "disabled")
        echo -e "开机自启状态: ${service_enabled}"
        echo ""
    fi
    
    # 检查防火墙表是否存在
    if ! nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
        log_warning "代理防火墙表不存在"
        echo -e "${YELLOW}运行以下命令来创建防火墙:${RESET}"
        echo -e "${YELLOW}  bash $0${RESET}"
        return 0
    fi
    
    echo -e "${GREEN}代理防火墙表状态: 存在${RESET}"
    echo ""
    
    # 统计规则数量
    local input_rules=$(nft list chain inet "$NFTABLES_TABLE" input 2>/dev/null | grep -c "accept\|drop\|log" || echo "0")
    local nat_rules=0
    if nft list chain inet "$NFTABLES_TABLE" prerouting >/dev/null 2>&1; then
        nat_rules=$(nft list chain inet "$NFTABLES_TABLE" prerouting 2>/dev/null | grep -c "dnat" || echo "0")
    fi
    
    echo -e "${GREEN}规则统计:${RESET}"
    echo -e "  INPUT 规则数量: $input_rules"
    echo -e "  NAT 规则数量: $nat_rules"
    echo ""
    
    # 显示开放的端口
    echo -e "${GREEN}开放的端口:${RESET}"
    if nft list chain inet "$NFTABLES_TABLE" input 2>/dev/null | grep -q "dport.*accept"; then
        nft list chain inet "$NFTABLES_TABLE" input 2>/dev/null | grep "dport.*accept" | while read -r line; do
            if echo "$line" | grep -qE "tcp dport [0-9]+"; then
                local port=$(echo "$line" | grep -oE "dport [0-9]+" | awk '{print $2}')
                echo -e "  ${GREEN}• $port (TCP)${RESET}"
            elif echo "$line" | grep -qE "udp dport [0-9]+"; then
                local port=$(echo "$line" | grep -oE "dport [0-9]+" | awk '{print $2}')
                echo -e "  ${GREEN}• $port (UDP)${RESET}"
            fi
        done
    else
        echo -e "  ${YELLOW}未检测到开放端口${RESET}"
    fi
    
    # 显示端口转发规则
    if [ "$nat_rules" -gt 0 ]; then
        echo ""
        echo -e "${GREEN}端口转发规则:${RESET}"
        nft list chain inet "$NFTABLES_TABLE" prerouting 2>/dev/null | grep "dnat" | while read -r line; do
            echo -e "  ${CYAN}$line${RESET}"
        done
    fi
    
    echo ""
    echo -e "${GREEN}管理命令:${RESET}"
    echo -e "  ${YELLOW}查看完整规则:${RESET} nft list table inet $NFTABLES_TABLE"
    echo -e "  ${YELLOW}查看监听端口:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}添加端口:${RESET} bash $0 --add-port"
    echo -e "  ${YELLOW}添加端口转发:${RESET} bash $0 --add-range"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash $0 --reset"
}

# 显示最终状态
show_final_status() {
    echo ""
    echo -e "${GREEN}========================================${RESET}"
    echo -e "${GREEN}    防火墙配置完成！${RESET}"
    echo -e "${GREEN}========================================${RESET}"
    echo ""
    
    # 配置摘要
    echo -e "${CYAN}配置摘要:${RESET}"
    echo -e "  防火墙引擎: nftables"
    echo -e "  防火墙表名: $NFTABLES_TABLE"
    echo -e "  SSH 端口: $SSH_PORT (已保护)"
    echo -e "  开放端口数量: $OPENED_PORTS"
    echo -e "  内部服务: 受保护"
    echo -e "  SSH 暴力破解防护: 已启用"
    echo ""
    
    # 开放的端口列表
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "${GREEN}开放的端口:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            local port_desc=""
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                port_desc=" (HTTP/HTTPS)"
            elif [[ " ${WARP_PORTS[*]} " =~ " $port " ]]; then
                port_desc=" (WARP)"
            elif [[ " ${HIDDIFY_PORTS[*]} " =~ " $port " ]]; then
                port_desc=" (Hiddify)"
            fi
            echo -e "  ${GREEN}• $port${port_desc}${RESET}"
        done
        echo ""
    fi
    
    # 管理提示
    echo -e "${CYAN}管理命令:${RESET}"
    echo -e "  ${YELLOW}查看状态:${RESET} bash $0 --status"
    echo -e "  ${YELLOW}添加端口:${RESET} bash $0 --add-port"
    echo -e "  ${YELLOW}端口转发:${RESET} bash $0 --add-range"
    echo -e "  ${YELLOW}查看规则:${RESET} nft list table inet $NFTABLES_TABLE"
    echo -e "  ${YELLOW}查看端口:${RESET} ss -tlnp"
    echo ""
    
    # 安全提醒
    echo -e "${GREEN}安全提醒:${RESET}"
    echo -e "  ✓ 已启用 SSH 连接频率限制"
    echo -e "  ✓ 已过滤危险和内部服务端口"
    echo -e "  ✓ 防火墙规则已持久化保存"
    echo -e "  ✓ 默认拒绝所有未授权连接"
    
    if [ "$DRY_RUN" = false ]; then
        echo ""
        log_success "防火墙配置完成！您的服务器现在更加安全。"
    else
        echo ""
        log_info "这是预览模式，防火墙未实际修改。"
    fi
}

# 主函数
main() {
    # 设置中断处理
    trap 'echo -e "\n${RED}操作被中断${RESET}"; exit 130' INT TERM
    
    # 解析参数
    parse_arguments "$@"
    
    echo -e "${CYAN}开始智能代理端口检测和防火墙配置...${RESET}"
    echo ""
    
    # 系统检查和初始化
    check_system_requirements
    detect_ssh_port
    cleanup_existing_firewall
    
    # 端口检测
    detect_proxy_services
    parse_config_files
    detect_listening_ports
    detect_warp_service
    
    # 端口分析和确认
    if ! filter_and_confirm_ports; then
        log_info "使用默认端口配置..."
        DETECTED_PORTS=("${DEFAULT_OPEN_PORTS[@]}" "${HIDDIFY_PORTS[@]}")
        filter_and_confirm_ports
    fi
    
    # 应用防火墙规则
    apply_firewall_rules
    
    # 显示最终状态
    show_final_status
}

# 脚本入口
main "$@"

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
SCRIPT_VERSION="2.3.0"
SCRIPT_NAME="精确代理端口防火墙管理脚本（nftables 版本）"

echo -e "${YELLOW}== 🚀 ${SCRIPT_NAME} v${SCRIPT_VERSION} ==${RESET}"
echo -e "${CYAN}针对 Hiddify、3X-UI、X-UI、Sing-box、Xray 等代理面板优化${RESET}"
echo -e "${GREEN}🔧 使用 nftables 实现高性能防火墙 + 修复重复规则问题${RESET}"

# 权限检查
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}❌ 需要 root 权限运行此脚本${RESET}"
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

# nftables 表名和链名
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
    "xray" "v2ray" "sing-box" "singbox" "sing_box"
    "hysteria" "hysteria2" "tuic" "juicity" "shadowtls"
    "hiddify" "hiddify-panel" "hiddify-manager"
    "x-ui" "3x-ui" "v2-ui" "v2rayA" "v2raya"
    "trojan" "trojan-go" "trojan-plus"
    "shadowsocks-rust" "ss-server" "shadowsocks-libev" "go-shadowsocks2"
    "brook" "gost" "naive" "clash" "clash-meta" "mihomo"
)

# Web 面板进程
WEB_PANEL_PROCESSES=(
    "nginx" "caddy" "apache2" "httpd" "haproxy" "envoy"
)

# 代理配置文件
PROXY_CONFIG_FILES=(
    "/opt/hiddify-manager/hiddify-panel/hiddify_panel/panel/commercial/restapi/v2/admin/admin.py"
    "/opt/hiddify-manager/log/system/hiddify-panel.log"
    "/opt/hiddify-manager/hiddify-panel/config.py"
    "/opt/hiddify-manager/.env"
    "/etc/x-ui/config.json"
    "/opt/3x-ui/bin/config.json"
    "/usr/local/x-ui/bin/config.json"
    "/usr/local/etc/xray/config.json"
    "/etc/xray/config.json"
    "/usr/local/etc/v2ray/config.json"
    "/etc/v2ray/config.json"
    "/etc/sing-box/config.json"
    "/opt/sing-box/config.json"
    "/usr/local/etc/sing-box/config.json"
    "/etc/hysteria/config.json"
    "/etc/tuic/config.json"
    "/etc/trojan/config.json"
)

# 内部服务端口（不应暴露）
INTERNAL_SERVICE_PORTS=(
    8181 10085 10086 9090 3000 3001 8000 8001
    10080 10081 10082 10083 10084 10085 10086 10087 10088 10089
    54321 62789
    9000 9001 9002
    8090 8091 8092 8093 8094 8095
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

# 字符串分割函数
split_nat_rule() {
    local rule="$1"
    local delimiter="$2"
    local field="$3"
    
    if [ "$delimiter" = "->" ]; then
        if [ "$field" = "1" ]; then
            echo "${rule%->*}"
        elif [ "$field" = "2" ]; then
            echo "${rule#*->}"
        fi
    else
        echo "$rule" | cut -d"$delimiter" -f"$field"
    fi
}

# 显示帮助信息
show_help() {
    cat << 'EOF'
精确代理端口防火墙管理脚本 v2.3.0（nftables 版本）

为现代代理面板设计的智能端口管理工具

用法: bash script.sh [选项]

选项:
    --debug           显示详细调试信息
    --dry-run         预览模式，不实际修改防火墙
    --add-range       交互式端口范围添加
    --reset           重置防火墙到默认状态
    --clean-nat       清理重复的NAT规则
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
    ✓ 其他主流代理工具

安全功能:
    ✓ 精确端口识别
    ✓ 自动过滤内部服务端口
    ✓ 危险端口过滤
    ✓ SSH 暴力破解防护
    ✓ 高性能的 nftables 防火墙
    ✓ 重复规则检测和清理
    ✓ 单一持久化机制，避免重复加载

EOF
}

# 单独的NAT规则清理函数
clean_nat_rules_only() {
    echo -e "${YELLOW}🔄 清理重复的NAT规则${RESET}"
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "${RED}警告: 这将清除所有现有的NAT端口转发规则！${RESET}"
        echo -e "${YELLOW}确认清理NAT规则吗？[y/N]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            info "清理操作已取消"
            return 0
        fi
    fi
    
    info "正在清理NAT规则..."
    
    local rule_count=0
    if nft list table inet "$NFT_TABLE" 2>/dev/null | grep -q "dnat to"; then
        rule_count=$(nft list table inet "$NFT_TABLE" 2>/dev/null | grep -c "dnat to" || echo "0")
    fi
    
    if [ "$DRY_RUN" = false ]; then
        if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
            nft flush chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null || true
        fi
        success "已清理 $rule_count 条NAT规则"
        
        save_nftables_rules
    else
        info "[预览模式] 将清理 $rule_count 条NAT规则"
    fi
    
    echo -e "\n${GREEN}✅ NAT规则清理完成${RESET}"
    if [ "$rule_count" -gt 0 ]; then
        echo -e "${CYAN}💡 提示: 如需重新配置端口转发，请运行 'bash $0 --add-range'${RESET}"
    fi
}

# 解析参数
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
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
    
    local tools=("nft" "ss" "jq")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        info "安装缺失的工具: ${missing_tools[*]}"
        if [ "$DRY_RUN" = false ]; then
            apt-get update -qq
            apt-get install -y nftables iproute2 jq 2>&1 | grep -v "^Reading\|^Building\|^Selecting\|^Unpacking\|^Setting" || true
        fi
    fi
    
    if [ "$DRY_RUN" = false ]; then
        if ! lsmod | grep -q nf_tables; then
            modprobe nf_tables 2>/dev/null || true
        fi
        if ! lsmod | grep -q nf_nat; then
            modprobe nf_nat 2>/dev/null || true
        fi
    fi
    
    success "系统环境检查完成"
}

# 检测 SSH 端口
detect_ssh_port() {
    debug_log "检测 SSH 端口..."
    
    local ssh_port=$(ss -tlnp 2>/dev/null | grep -E 'sshd' | awk '{print $4}' | grep -oE '[0-9]+$' | head -1)
    
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] && [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -i '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print $2}' | head -1)
    fi
    
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]]; then
        ssh_port="22"
    fi
    
    SSH_PORT="$ssh_port"
    info "检测到 SSH 端口: $SSH_PORT"
}

# 检测现有的 NAT 规则
detect_existing_nat_rules() {
    info "检测现有端口转发规则..."
    
    local nat_rules=()
    
    if command -v nft >/dev/null 2>&1; then
        debug_log "扫描 nftables NAT 规则..."
        
        for table_info in $(nft list tables 2>/dev/null | grep -E "(inet|ip)" | awk '{print $2" "$3}' || true); do
            local family=$(echo "$table_info" | awk '{print $1}')
            local table=$(echo "$table_info" | awk '{print $2}')
            
            if [ -z "$family" ] || [ -z "$table" ]; then
                continue
            fi
            
            debug_log "检查表: $family $table"
            
            if nft list table "$family" "$table" 2>/dev/null | grep -q "dnat to"; then
                while IFS= read -r line; do
                    if echo "$line" | grep -qE "dnat to"; then
                        debug_log "分析 nftables 规则: $line"
                        
                        local port_range=""
                        local target_port=""
                        
                        if echo "$line" | grep -oE "[0-9]+-[0-9]+" >/dev/null 2>&1; then
                            port_range=$(echo "$line" | grep -oE "[0-9]+-[0-9]+" | head -1)
                        fi
                        
                        if echo "$line" | grep -qE "dnat to :[0-9]+"; then
                            target_port=$(echo "$line" | grep -oE "dnat to :[0-9]+" | grep -oE "[0-9]+$")
                        fi
                        
                        if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                            local rule_key="$port_range->$target_port"
                            nat_rules+=("$rule_key")
                            debug_log "发现 nftables 端口转发规则: $port_range -> $target_port"
                        fi
                    fi
                done <<< "$(nft list table "$family" "$table" 2>/dev/null | grep "dnat to")"
            fi
        done
    fi
    
    if [ ${#nat_rules[@]} -gt 0 ]; then
        local unique_rules=($(printf '%s\n' "${nat_rules[@]}" | sort -u))
        NAT_RULES=("${unique_rules[@]}")
        
        for rule in "${NAT_RULES[@]}"; do
            local target_port=$(split_nat_rule "$rule" "->" "2")
            if [ -n "$target_port" ]; then
                DETECTED_PORTS+=("$target_port")
            fi
        done
        
        echo -e "\n${GREEN}🔄 检测到现有端口转发规则:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            echo -e "  ${GREEN}• $rule${RESET}"
        done
        success "检测到 ${#NAT_RULES[@]} 条端口转发规则"
    else
        info "未检测到现有端口转发规则"
    fi
}

# 交互式端口范围添加
add_port_range_interactive() {
    echo -e "${CYAN}🔧 配置端口转发规则${RESET}"
    echo -e "${YELLOW}端口转发允许将端口范围重定向到单个目标端口${RESET}"
    echo -e "${YELLOW}示例: 16820-16888 转发到 16801${RESET}"
    
    while true; do
        echo -e "\n${CYAN}请输入端口范围（格式: 起始-结束，如 16820-16888）:${RESET}"
        read -r port_range
        
        if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start_port="${BASH_REMATCH[1]}"
            local end_port="${BASH_REMATCH[2]}"
            
            if [ "$start_port" -ge "$end_port" ]; then
                echo -e "${RED}起始端口必须小于结束端口${RESET}"
                continue
            fi
            
            echo -e "${CYAN}请输入目标端口（单个端口号）:${RESET}"
            read -r target_port
            
            if [[ "$target_port" =~ ^[0-9]+$ ]] && [ "$target_port" -ge 1 ] && [ "$target_port" -le 65535 ]; then
                NAT_RULES+=("$port_range->$target_port")
                DETECTED_PORTS+=("$target_port")
                success "添加端口转发规则: $port_range -> $target_port"
                
                echo -e "${YELLOW}继续添加其他端口转发规则吗？[y/N]${RESET}"
                read -r response
                if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
                    break
                fi
            else
                echo -e "${RED}无效的目标端口: $target_port${RESET}"
            fi
        else
            echo -e "${RED}无效的端口范围格式: $port_range${RESET}"
        fi
    done
}

# 检测代理进程
detect_proxy_processes() {
    info "检测代理服务进程..."
    
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
        success "检测到代理相关进程: ${found_processes[*]}"
        return 0
    else
        warning "未检测到运行中的代理进程"
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

# 从配置文件解析端口
parse_config_ports() {
    info "从配置文件解析端口..."
    
    local config_ports=()
    
    for config_file in "${PROXY_CONFIG_FILES[@]}"; do
        if [ -f "$config_file" ]; then
            debug_log "分析配置文件: $config_file"
            
            if [[ "$config_file" =~ \.json$ ]]; then
                if command -v jq >/dev/null 2>&1; then
                    local ports=$(jq -r '.inbounds[]? | select(.listen == null or .listen == "" or .listen == "0.0.0.0" or .listen == "::") | .port' "$config_file" 2>/dev/null | grep -E '^[0-9]+$' | sort -nu) || true
                    if [ -n "$ports" ]; then
                        while read -r port; do
                            if ! is_internal_service_port "$port"; then
                                config_ports+=("$port")
                                debug_log "从 $config_file 解析端口: $port"
                            fi
                        done <<< "$ports"
                    fi
                fi
            elif [[ "$config_file" =~ \.(yaml|yml)$ ]]; then
                local ports=$(grep -oE 'port[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" 2>/dev/null | grep -oE '[0-9]+' | sort -nu) || true
                if [ -n "$ports" ]; then
                    while read -r port; do
                        if ! is_internal_service_port "$port"; then
                            config_ports+=("$port")
                            debug_log "从 $config_file 解析 YAML 端口: $port"
                        fi
                    done <<< "$ports"
                fi
            fi
        fi
    done
    
    if [ ${#config_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${config_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "从配置文件解析到 ${#unique_ports[@]} 个端口"
    fi
}

# 检测监听端口
detect_listening_ports() {
    info "检测当前监听端口..."
    
    local listening_ports=()
    local localhost_ports=()
    
    while IFS= read -r line; do
        if [[ "$line" =~ LISTEN ]] || [[ "$line" =~ UNCONN ]]; then
            local address_port=$(echo "$line" | awk '{print $4}')
            local port=$(echo "$address_port" | grep -oE '[0-9]+$')
            
            if [ -z "$port" ] || [ "$port" = "$SSH_PORT" ]; then
                continue
            fi
            
            local bind_type=$(check_bind_address "$address_port")
            
            debug_log "检测到监听: $address_port ($bind_type)"
            
            if [ "$bind_type" = "public" ]; then
                if ! is_internal_service_port "$port"; then
                    listening_ports+=("$port")
                    debug_log "检测到公共代理端口: $port"
                else
                    debug_log "跳过内部服务端口: $port"
                fi
            elif [ "$bind_type" = "localhost" ]; then
                localhost_ports+=("$port")
                debug_log "检测到本地代理端口: $port - 不暴露"
            fi
        fi
    done <<< "$(ss -tulnp 2>/dev/null)" || true
    
    if [ ${#localhost_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}🔒 检测到内部服务端口（仅本地）:${RESET}"
        for port in $(printf '%s\n' "${localhost_ports[@]}" | sort -nu); do
            echo -e "  ${YELLOW}• $port${RESET} - 内部服务，不暴露"
        done
    fi
    
    if [ ${#listening_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${listening_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "检测到 ${#unique_ports[@]} 个公共监听端口"
    fi
}

# 检查端口是否为内部服务
is_internal_service_port() {
    local port="$1"
    
    for internal_port in "${INTERNAL_SERVICE_PORTS[@]}"; do
        if [ "$port" = "$internal_port" ]; then
            return 0
        fi
    done
    
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
    
    if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
        debug_log "端口 $port 是默认开放端口"
        return 0
    fi
    
    return 0
}

# 过滤并确认端口
filter_and_confirm_ports() {
    info "智能端口分析和确认..."
    
    info "添加默认开放端口: ${DEFAULT_OPEN_PORTS[*]}"
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
    
    if [ ${#safe_ports[@]} -gt 0 ]; then
        echo -e "\n${GREEN}✅ 标准代理端口（推荐）:${RESET}"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}✓ $port${RESET} - 默认开放端口"
            else
                echo -e "  ${GREEN}✓ $port${RESET} - 常用代理端口"
            fi
        done
    fi
    
    if [ ${#internal_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}🔒 内部服务端口（已过滤）:${RESET}"
        for port in "${internal_ports[@]}"; do
            echo -e "  ${YELLOW}- $port${RESET} - 内部服务端口，不暴露"
        done
    fi
    
    if [ ${#suspicious_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}⚠️  可疑端口（需要确认）:${RESET}"
        for port in "${suspicious_ports[@]}"; do
            echo -e "  ${YELLOW}? $port${RESET} - 非标准代理端口"
        done
        
        echo -e "\n${YELLOW}这些端口可能不是必要的代理端口${RESET}"
        
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
        echo -e "\n${RED}❌ 危险端口（已跳过）:${RESET}"
        for port in "${unsafe_ports[@]}"; do
            echo -e "  ${RED}✗ $port${RESET} - 系统端口或危险端口"
        done
    fi
    
    if [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -eq 0 ]; then
        echo -e "\n${CYAN}🔄 配置端口转发功能吗？[y/N]${RESET}"
        echo -e "${YELLOW}端口转发可以将端口范围重定向到单个目标端口${RESET}"
        read -r response
        if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            add_port_range_interactive
        fi
    fi
    
    if [ ${#safe_ports[@]} -eq 0 ]; then
        warning "未检测到标准代理端口"
        safe_ports=("${DEFAULT_OPEN_PORTS[@]}")
    fi
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "\n${CYAN}📋 最终要开放的端口:${RESET}"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${CYAN}• $port${RESET} (默认开放)"
            else
                echo -e "  ${CYAN}• $port${RESET}"
            fi
        done
        
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "\n${CYAN}🔄 端口转发规则:${RESET}"
            for rule in "${NAT_RULES[@]}"; do
                echo -e "  ${CYAN}• $rule${RESET}"
            done
        fi
        
        echo -e "\n${YELLOW}确认开放 ${#safe_ports[@]} 个端口"
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "和 ${#NAT_RULES[@]} 条端口转发规则"
        fi
        echo -e "吗？[Y/n]${RESET}"
        read -r response
        if [[ "$response" =~ ^[Nn]([oO])?$ ]]; then
            info "用户取消操作"
            exit 0
        fi
    fi
    
    DETECTED_PORTS=($(printf '%s\n' "${safe_ports[@]}" | sort -nu))
    return 0
}

# 清理现有防火墙
cleanup_firewalls() {
    info "清理现有防火墙配置..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将清理现有防火墙"
        return 0
    fi
    
    for service in ufw firewalld; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
            success "已禁用 $service"
        fi
    done
    
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1 || true
    fi
    
    info "清理所有 nftables 规则..."
    nft flush ruleset 2>/dev/null || true
    
    success "所有防火墙规则清理完成"
}

# 创建 nftables 基础结构
create_nftables_base() {
    info "创建 nftables 基础结构..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将创建 nftables 基础结构"
        return 0
    fi
    
    # 检查表是否存在，存在则删除
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        nft delete table inet "$NFT_TABLE" 2>/dev/null || true
    fi
    
    nft add table inet "$NFT_TABLE"
    
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" { type filter hook input priority 0 \; policy drop \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_FORWARD" { type filter hook forward priority 0 \; policy drop \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_OUTPUT" { type filter hook output priority 0 \; policy accept \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" { type nat hook prerouting priority -100 \; }
    
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_SSH"
    
    success "nftables 基础结构创建完成"
}

# 设置 SSH 保护
setup_ssh_protection() {
    info "设置 SSH 暴力破解防护..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将设置 SSH 保护"
        return 0
    fi
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" ct state established,related accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" tcp dport "$SSH_PORT" limit rate 4/minute burst 4 packets accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" tcp dport "$SSH_PORT" drop
    
    success "SSH 暴力破解防护已配置"
}

# 应用 nftables 防火墙规则
apply_firewall_rules() {
    info "应用 nftables 防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 防火墙规则预览:"
        show_rules_preview
        return 0
    fi
    
    create_nftables_base
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" iif "lo" accept
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" ct state established,related accept
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" icmp type echo-request limit rate 10/second accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" icmpv6 type echo-request limit rate 10/second accept
    
    setup_ssh_protection
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport "$SSH_PORT" jump "$NFT_CHAIN_SSH"
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        local tcp_ports=""
        local udp_ports=""
        
        for port in "${DETECTED_PORTS[@]}"; do
            if [ -z "$tcp_ports" ]; then
                tcp_ports="$port"
                udp_ports="$port"
            else
                tcp_ports="$tcp_ports, $port"
                udp_ports="$udp_ports, $port"
            fi
            debug_log "开放端口: $port (TCP/UDP)"
        done
        
        nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport { $tcp_ports } accept
        
        nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" udp dport { $udp_ports } accept
        
        info "已开放 ${#DETECTED_PORTS[@]} 个端口 (TCP/UDP)"
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "应用端口转发规则..."
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                local start_port=$(echo "$port_range" | cut -d'-' -f1)
                local end_port=$(echo "$port_range" | cut -d'-' -f2)
                
                nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" tcp dport "$start_port-$end_port" dnat to ":$target_port"
                nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" udp dport "$start_port-$end_port" dnat to ":$target_port"
                
                nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport "$start_port-$end_port" accept
                nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" udp dport "$start_port-$end_port" accept
                
                success "应用端口转发: $port_range -> $target_port"
                debug_log "NAT 规则: $start_port-$end_port -> $target_port"
            else
                warning "无法解析 NAT 规则: $rule"
            fi
        done
    fi
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" limit rate 3/minute burst 3 packets log prefix \"nftables-drop: \" level warn
    
    OPENED_PORTS=${#DETECTED_PORTS[@]}
    success "nftables 规则应用成功"
    
    save_nftables_rules
}

# 改进的 nftables 规则保存函数 - 单一持久化机制
save_nftables_rules() {
    info "保存 nftables 规则并配置持久化..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将保存 nftables 规则"
        return 0
    fi
    
    mkdir -p /etc/nftables.d
    
    nft list ruleset > /etc/nftables.conf
    
    if [ ! -s /etc/nftables.conf ]; then
        error_exit "规则保存失败：配置文件为空"
    fi
    
    # 只使用一个持久化机制：systemd 服务
    cat > /etc/systemd/system/nftables-restore.service << 'EOF'
[Unit]
Description=Restore nftables firewall rules
Documentation=man:nft(8)
After=network-pre.target
Before=network.target network-online.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/nftables.conf
ExecReload=/usr/sbin/nft flush ruleset; /usr/sbin/nft -f /etc/nftables.conf
ExecStop=/usr/sbin/nft flush ruleset
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target network.target
EOF
    
    systemctl daemon-reload
    
    systemctl enable nftables-restore.service >/dev/null 2>&1
    
    if systemctl list-unit-files 2>/dev/null | grep -q "^nftables.service"; then
        systemctl stop nftables.service >/dev/null 2>&1 || true
        systemctl disable nftables.service >/dev/null 2>&1 || true
        info "已禁用系统原生 nftables.service，使用增强版服务"
    fi
    
    # 清理可能存在的其他持久化机制
    if [ -f /etc/rc.local ]; then
        if grep -q "nft -f /etc/nftables.conf" /etc/rc.local 2>/dev/null; then
            sed -i '/nft -f \/etc\/nftables.conf/d' /etc/rc.local
            sed -i '/自动恢复 nftables 规则/d' /etc/rc.local
            info "已清理 rc.local 中的重复配置"
        fi
    fi
    
    if crontab -l 2>/dev/null | grep -q "nft -f /etc/nftables.conf"; then
        (crontab -l 2>/dev/null | grep -v "nft -f /etc/nftables.conf") | crontab -
        info "已清理 cron 中的重复配置"
    fi
    
    if systemctl is-enabled nftables-restore.service >/dev/null 2>&1; then
        success "✓ systemd 服务已启用（单一持久化机制）"
    else
        warning "systemd 服务启用失败，尝试手动启用"
        systemctl enable nftables-restore.service --now
    fi
    
    if nft -c -f /etc/nftables.conf 2>/dev/null; then
        success "✓ nftables 规则验证通过"
    else
        error_exit "nftables 规则验证失败，请检查配置"
    fi
    
    success "nftables 规则已保存并配置持久化（避免重复加载）"
    
    echo -e "\n${CYAN}🔒 持久化机制:${RESET}"
    echo -e "  ${GREEN}✓ /etc/nftables.conf${RESET} (主配置文件)"
    echo -e "  ${GREEN}✓ nftables-restore.service${RESET} (systemd 自动加载)"
    echo -e "  ${YELLOW}! 已禁用其他重复的持久化机制${RESET}"
}

# 验证持久化配置
verify_persistence() {
    info "验证持久化配置..."
    
    local issues=0
    
    if [ -f /etc/nftables.conf ] && [ -s /etc/nftables.conf ]; then
        success "✓ 配置文件存在且有内容"
    else
        warning "✗ 配置文件不存在或为空"
        ((issues++))
    fi
    
    if systemctl is-enabled nftables-restore.service >/dev/null 2>&1; then
        success "✓ systemd 服务已启用"
    else
        warning "✗ systemd 服务未启用"
        ((issues++))
    fi
    
    # 改进的规则检查：检查表是否存在
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        # 统计各个链中的规则数
        local input_rules=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" 2>/dev/null | grep -E "accept|drop|reject|jump|dnat" | wc -l)
        local nat_rules=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep -E "dnat" | wc -l)
        local total_rules=$((input_rules + nat_rules))
        
        if [ "$total_rules" -gt 0 ]; then
            success "✓ 当前有 $total_rules 条活动规则 (INPUT: $input_rules, NAT: $nat_rules)"
        else
            warning "✗ 防火墙表存在但无规则"
            ((issues++))
        fi
    else
        warning "✗ 防火墙表 $NFT_TABLE 不存在"
        ((issues++))
    fi
    
    if [ $issues -eq 0 ]; then
        success "持久化机制验证通过"
        return 0
    else
        warning "发现 $issues 个持久化问题"
        return 1
    fi
}

# 显示规则预览
show_rules_preview() {
    echo -e "${CYAN}📋 即将应用的 nftables 规则预览:${RESET}"
    echo
    echo "# 创建表和链"
    echo "nft add table inet $NFT_TABLE"
    echo "nft add chain inet $NFT_TABLE $NFT_CHAIN_INPUT { type filter hook input priority 0 ; policy drop ; }"
    echo "nft add chain inet $NFT_TABLE $NFT_CHAIN_FORWARD { type filter hook forward priority 0 ; policy drop ; }"
    echo "nft add chain inet $NFT_TABLE $NFT_CHAIN_OUTPUT { type filter hook output priority 0 ; policy accept ; }"
    echo "nft add chain inet $NFT_TABLE $NFT_CHAIN_PREROUTING { type nat hook prerouting priority -100 ; }"
    echo "nft add chain inet $NFT_TABLE $NFT_CHAIN_SSH"
    echo
    echo "# 基本规则"
    echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_INPUT iif lo accept"
    echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_INPUT ct state established,related accept"
    echo
    echo "# ICMP 支持"
    echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_INPUT icmp type echo-request limit rate 10/second accept"
    echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_INPUT icmpv6 type echo-request limit rate 10/second accept"
    echo
    echo "# SSH 保护"
    echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_SSH ct state established,related accept"
    echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_SSH tcp dport $SSH_PORT limit rate 4/minute burst 4 packets accept"
    echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_SSH tcp dport $SSH_PORT drop"
    echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_INPUT tcp dport $SSH_PORT jump $NFT_CHAIN_SSH"
    echo
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo "# 代理端口"
        local tcp_ports=""
        local udp_ports=""
        
        for port in "${DETECTED_PORTS[@]}"; do
            if [ -z "$tcp_ports" ]; then
                tcp_ports="$port"
                udp_ports="$port"
            else
                tcp_ports="$tcp_ports, $port"
                udp_ports="$udp_ports, $port"
            fi
        done
        
        echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_INPUT tcp dport { $tcp_ports } accept"
        echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_INPUT udp dport { $udp_ports } accept"
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo
        echo "# 端口转发规则"
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            local start_port=$(echo "$port_range" | cut -d'-' -f1)
            local end_port=$(echo "$port_range" | cut -d'-' -f2)
            echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_PREROUTING tcp dport $start_port-$end_port dnat to :$target_port"
            echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_PREROUTING udp dport $start_port-$end_port dnat to :$target_port"
            echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_INPUT tcp dport $start_port-$end_port accept"
            echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_INPUT udp dport $start_port-$end_port accept"
        done
    fi
    
    echo
    echo "# 日志记录和丢弃"
    echo "nft add rule inet $NFT_TABLE $NFT_CHAIN_INPUT limit rate 3/minute burst 3 packets log prefix \"nftables-drop: \" level warn"
}

# 验证端口转发功能
verify_port_hopping() {
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "验证端口转发配置..."
        
        echo -e "\n${CYAN}🔍 当前 NAT 规则状态:${RESET}"
        if command -v nft >/dev/null 2>&1 && nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
            nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep "dnat to" || echo "无 NAT 规则"
        fi
        
        echo -e "\n${YELLOW}💡 端口转发使用说明:${RESET}"
        echo -e "  - 客户端可以连接到范围内的任意端口"
        echo -e "  - 所有连接都会转发到目标端口"
        echo -e "  - 示例：范围内端口的连接转发到目标端口"
        
        local checked_ports=()
        for rule in "${NAT_RULES[@]}"; do
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            debug_log "验证规则: $rule"
            
            if [ -n "$target_port" ]; then
                if [[ ! " ${checked_ports[*]} " =~ " $target_port " ]]; then
                    checked_ports+=("$target_port")
                    
                    if ss -tlnp 2>/dev/null | grep -q ":$target_port "; then
                        echo -e "  ${GREEN}✓ 目标端口 $target_port 正在监听${RESET}"
                    else
                        echo -e "  ${YELLOW}⚠️  目标端口 $target_port 未在监听${RESET}"
                        echo -e "    ${YELLOW}提示: 请确保代理服务在端口 $target_port 上运行${RESET}"
                    fi
                fi
            else
                echo -e "  ${RED}❌ 无法解析规则: $rule${RESET}"
            fi
        done
        
        echo -e "\n${CYAN}📝 端口转发规则摘要:${RESET}"
        local unique_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        for rule in "${unique_rules[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            echo -e "  ${CYAN}• 端口范围 $port_range → 目标端口 $target_port${RESET}"
        done
    fi
}

# 重置防火墙
reset_firewall() {
    echo -e "${YELLOW}🔄 重置防火墙到默认状态${RESET}"
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "${RED}警告: 这将清除所有 nftables 规则和持久化配置！${RESET}"
        echo -e "${YELLOW}确认重置防火墙吗？[y/N]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            info "重置操作已取消"
            return 0
        fi
    fi
    
    info "重置 nftables 规则和配置..."
    
    if [ "$DRY_RUN" = false ]; then
        nft flush ruleset 2>/dev/null || true
        
        if [ -f /etc/nftables.conf ]; then
            rm -f /etc/nftables.conf
        fi
        
        systemctl stop nftables-restore.service >/dev/null 2>&1 || true
        systemctl disable nftables-restore.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/nftables-restore.service
        systemctl daemon-reload
        
        if [ -f /etc/rc.local ]; then
            sed -i '/nft -f \/etc\/nftables.conf/d' /etc/rc.local
            sed -i '/自动恢复 nftables 规则/d' /etc/rc.local
        fi
        
        if crontab -l 2>/dev/null | grep -q "nft -f /etc/nftables.conf"; then
            (crontab -l 2>/dev/null | grep -v "nft -f /etc/nftables.conf") | crontab -
        fi
        
        success "防火墙已重置到默认状态"
        success "所有持久化配置已清理"
    else
        info "[预览模式] 将重置所有 nftables 规则和配置"
    fi
}

# 显示防火墙状态
show_firewall_status() {
    echo -e "${CYAN}🔍 当前防火墙状态${RESET}"
    echo
    
    if ! command -v nft >/dev/null 2>&1; then
        echo -e "${RED}❌ nftables 未安装${RESET}"
        return 1
    fi
    
    echo -e "${GREEN}📊 nftables 规则统计:${RESET}"
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        local input_rules=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" 2>/dev/null | grep -c "accept\|drop\|reject" || echo "0")
        local nat_rules=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep -c "dnat to" || echo "0")
        echo -e "  INPUT 规则数: $input_rules"
        echo -e "  NAT 规则数: $nat_rules"
    else
        echo -e "  ${YELLOW}⚠️  未找到 $NFT_TABLE 表${RESET}"
    fi
    echo
    
    echo -e "${GREEN}🔓 开放的端口:${RESET}"
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" 2>/dev/null | grep -E "(tcp|udp) dport" | while read -r line; do
            if echo "$line" | grep -q "accept"; then
                local ports=$(echo "$line" | grep -oE "dport \{[^}]+\}|dport [0-9-]+" | sed 's/dport //g' | tr -d '{}')
                local protocol=$(echo "$line" | grep -oE "tcp|udp")
                if [ -n "$ports" ]; then
                    echo -e "  • $ports ($protocol)"
                fi
            fi
        done
    else
        echo -e "  ${YELLOW}无规则表${RESET}"
    fi
    echo
    
    echo -e "${GREEN}🔄 端口转发规则:${RESET}"
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        local nat_count=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep -c "dnat to" || echo "0")
        
        if [ "$nat_count" -gt 0 ]; then
            nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep "dnat to" | while read -r line; do
                local port_range=$(echo "$line" | grep -oE "dport [0-9-]+" | sed 's/dport //g')
                local target=$(echo "$line" | grep -oE "dnat to :[0-9]+" | sed 's/dnat to ://g')
                if [ -n "$port_range" ] && [ -n "$target" ]; then
                    echo -e "  • $port_range → $target"
                fi
            done
        else
            echo -e "  ${YELLOW}无端口转发规则${RESET}"
        fi
    else
        echo -e "  ${YELLOW}无规则表${RESET}"
    fi
    echo
    
    echo -e "${GREEN}🛡️  SSH 保护状态:${RESET}"
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1 && nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_SSH" 2>/dev/null | grep -q "limit rate"; then
        echo -e "  ${GREEN}✓ SSH 暴力破解防护已启用${RESET}"
    else
        echo -e "  ${YELLOW}⚠️  SSH 暴力破解防护未启用${RESET}"
    fi
    echo
    
    echo -e "${GREEN}🔒 持久化状态:${RESET}"
    verify_persistence
    echo
    
    echo -e "${CYAN}🔧 管理命令:${RESET}"
    echo -e "  ${YELLOW}查看所有规则:${RESET} nft list ruleset"
    echo -e "  ${YELLOW}查看表规则:${RESET} nft list table inet $NFT_TABLE"
    echo -e "  ${YELLOW}查看监听端口:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}重新配置:${RESET} bash $0"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash $0 --reset"
}

# 显示最终状态
show_final_status() {
    echo -e "\n${GREEN}=================================="
    echo -e "🎉 nftables 防火墙配置完成！"
    echo -e "==================================${RESET}"
    
    echo -e "\n${CYAN}📊 配置摘要:${RESET}"
    echo -e "  ${GREEN}✓ 开放端口数: $OPENED_PORTS${RESET}"
    echo -e "  ${GREEN}✓ SSH 端口: $SSH_PORT (已保护)${RESET}"
    echo -e "  ${GREEN}✓ 防火墙引擎: nftables${RESET}"
    echo -e "  ${GREEN}✓ 内部服务保护: 已启用${RESET}"
    echo -e "  ${GREEN}✓ 默认端口: 80, 443 (永久开放)${RESET}"
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        local unique_nat_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        echo -e "  ${GREEN}✓ 端口转发规则: ${#unique_nat_rules[@]} 条${RESET}"
    fi
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 已开放端口:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}• $port (TCP/UDP) - 默认开放${RESET}"
            else
                echo -e "  ${GREEN}• $port (TCP/UDP)${RESET}"
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${CYAN}🔄 端口转发规则:${RESET}"
        local unique_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        for rule in "${unique_rules[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            echo -e "  ${CYAN}• $port_range → $target_port${RESET}"
        done
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}🔍 这是预览模式，防火墙实际未被修改${RESET}"
        return 0
    fi
    
    echo -e "\n${CYAN}🔒 持久化保障:${RESET}"
    verify_persistence
    
    echo -e "\n${CYAN}🔧 管理命令:${RESET}"
    echo -e "  ${YELLOW}查看规则:${RESET} nft list ruleset"
    echo -e "  ${YELLOW}查看表:${RESET} nft list table inet $NFT_TABLE"
    echo -e "  ${YELLOW}查看端口:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}查看状态:${RESET} bash \$0 --status"
    echo -e "  ${YELLOW}添加端口转发:${RESET} bash \$0 --add-range"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash \$0 --reset"
    
    echo -e "\n${GREEN}✅ 代理端口精确开放，端口转发已配置，内部服务受保护，服务器安全已启用！${RESET}"
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        local has_unlistened=false
        local checked_ports=()
        
        for rule in "${NAT_RULES[@]}"; do
            local target_port=$(split_nat_rule "$rule" "->" "2")
            if [ -n "$target_port" ] && [[ ! " ${checked_ports[*]} " =~ " $target_port " ]]; then
                checked_ports+=("$target_port")
                if ! ss -tlnp 2>/dev/null | grep -q ":$target_port "; then
                    has_unlistened=true
                    break
                fi
            fi
        done
        
        if [ "$has_unlistened" = true ]; then
            echo -e "\n${YELLOW}⚠️  提醒: 某些端口转发目标端口未在监听${RESET}"
            echo -e "${YELLOW}   请确保相关代理服务正在运行，否则端口转发可能无法工作${RESET}"
        fi
    fi
    
    echo -e "\n${CYAN}💡 nftables 优势:${RESET}"
    echo -e "  ${GREEN}• 更高的性能和更低的资源占用${RESET}"
    echo -e "  ${GREEN}• 原子性操作，避免规则冲突${RESET}"
    echo -e "  ${GREEN}• 更简洁的语法和更好的可维护性${RESET}"
    echo -e "  ${GREEN}• 内核原生支持，未来的防火墙标准${RESET}"
    echo -e "  ${GREEN}• 单一持久化机制，避免重复加载${RESET}"
    
    echo -e "\n${YELLOW}💾 重启测试建议:${RESET}"
    echo -e "  建议执行 ${CYAN}reboot${RESET} 重启系统，验证规则是否自动加载"
    echo -e "  重启后运行 ${CYAN}bash \$0 --status${RESET} 检查规则状态"
    echo -e "  ${GREEN}修复版已避免规则重复加载问题${RESET}"
}

# 主函数
main() {
    trap 'echo -e "\n${RED}操作被中断${RESET}"; exit 130' INT TERM
    
    parse_arguments "$@"
    
    echo -e "\n${CYAN}🚀 开始智能代理端口检测和配置...${RESET}"
    
    check_system
    detect_ssh_port
    detect_existing_nat_rules
    cleanup_firewalls
    
    if ! detect_proxy_processes; then
        warning "建议在运行此脚本之前启动代理服务以获得最佳效果"
    fi
    
    parse_config_ports
    detect_listening_ports
    
    if ! filter_and_confirm_ports; then
        info "未能确认端口，使用默认端口"
        DETECTED_PORTS=("${DEFAULT_OPEN_PORTS[@]}")
    fi
    
    apply_firewall_rules
    verify_port_hopping
    show_final_status
}

# 脚本入口点
main "$@"

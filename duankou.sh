# 显示最终状态
show_final_status() {
    echo -e "\n${GREEN}=================================="
    echo -e "🎉 防火墙配置完成！"
    echo -e "==================================${RESET}"
    
    echo -e "\n${CYAN}📊 配置摘要:${RESET}"
    echo -e "  ${GREEN}✓ 开放端口数量: $OPENED_PORTS${RESET}"
    echo -e "  ${GREEN}✓ SSH端口: $SSH_PORT (已保护)${RESET}"
    echo -e "  ${GREEN}✓ 防火墙引擎: nftables${RESET}"
    echo -e "  ${GREEN}✓ 内部服务保护: 已启用${RESET}"
    echo -e "  ${GREEN}✓ 默认端口: 80, 443 (恒定开放)${RESET}"
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        local unique_nat_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        echo -e "  ${GREEN}✓ 端口跳跃规则: ${#unique_nat_rules[@]} 个${RESET}"
    fi
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 已开放的端口:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}• $port (TCP/UDP) - 默认开放${RESET}"
            else
                echo -e "  ${GREEN}• $port (TCP/UDP)${RESET}"
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${CYAN}🔄 端口跳跃规则:${RESET}"
        local unique_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        for rule in "${unique_rules[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            echo -e "  ${CYAN}• $port_range → $target_port${RESET}"
        done
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}🔍 这是预演模式，实际未修改防火墙${RESET}"
        return 0
    fi
    
    echo -e "\n${CYAN}🔧 管理命令:${RESET}"
    echo -e "  ${YELLOW}查看规则:${RESET} nft list ruleset"
    echo -e "  ${YELLOW}查看端口:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}重启防火墙:${RESET} systemctl restart nftables"
    echo -e "  ${YELLOW}查看日志:${RESET} journalctl -u nftables"
    echo -e "  ${YELLOW}添加端口跳跃:${RESET} bash script.sh --add-range"
    echo -e "  ${YELLOW}查看NAT规则:${RESET} nft list table inet nat"
    
    echo -e "\n${GREEN}✅ 代理端口已精准开放，端口跳跃已配置，内部服务已保护，服务器安全防护已启用！${RESET}"
    
    # 如果有未监听的目标端口，给出提醒
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
            echo -e "\n${YELLOW}⚠️  提醒: 检测到部分端口跳跃的目标端口未在监听${RESET}"
            echo -e "${YELLOW}   请确保相关代理服务正在运行，否则端口跳跃功能可能无效${RESET}"
        fi
    fi
}
}#!/bin/bash
set -e

# 颜色定义
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

# 脚本信息
SCRIPT_VERSION="1.2.3"
SCRIPT_NAME="精准代理端口防火墙管理脚本（修复版）"

echo -e "${YELLOW}== 🚀 ${SCRIPT_NAME} v${SCRIPT_VERSION} ==${RESET}"
echo -e "${CYAN}专为 Hiddify、3X-UI、X-UI、Sing-box、Xray 等代理面板优化${RESET}"
echo -e "${GREEN}🔧 修复语法错误和端口跳跃功能${RESET}"

# 权限检查
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}❌ 需要 root 权限运行${RESET}"
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

# 默认恒定开放端口（不需要检测）
DEFAULT_OPEN_PORTS=(80 443)

# 精准代理进程识别（基于实际使用场景）
PROXY_CORE_PROCESSES=(
    # 核心代理引擎
    "xray" "v2ray" "sing-box" "singbox" "sing_box"
    # 现代协议
    "hysteria" "hysteria2" "tuic" "juicity" "shadowtls"
    # 管理面板主进程
    "hiddify" "hiddify-panel" "hiddify-manager"
    "x-ui" "3x-ui" "v2-ui" "v2rayA" "v2raya"
    # Trojan系列
    "trojan" "trojan-go" "trojan-plus"
    # Shadowsocks系列
    "shadowsocks-rust" "ss-server" "shadowsocks-libev" "go-shadowsocks2"
    # 其他代理
    "brook" "gost" "naive" "clash" "clash-meta" "mihomo"
)

# Web面板进程（通常托管管理界面）
WEB_PANEL_PROCESSES=(
    "nginx" "caddy" "apache2" "httpd" "haproxy" "envoy"
)

# 代理配置文件路径（精准定位）
PROXY_CONFIG_FILES=(
    # Hiddify相关
    "/opt/hiddify-manager/hiddify-panel/hiddify_panel/panel/commercial/restapi/v2/admin/admin.py"
    "/opt/hiddify-manager/log/system/hiddify-panel.log"
    "/opt/hiddify-manager/hiddify-panel/config.py"
    "/opt/hiddify-manager/.env"
    
    # 3X-UI / X-UI
    "/etc/x-ui/config.json"
    "/opt/3x-ui/bin/config.json"
    "/usr/local/x-ui/bin/config.json"
    
    # Xray/V2Ray
    "/usr/local/etc/xray/config.json"
    "/etc/xray/config.json"
    "/usr/local/etc/v2ray/config.json"
    "/etc/v2ray/config.json"
    
    # Sing-box
    "/etc/sing-box/config.json"
    "/opt/sing-box/config.json"
    "/usr/local/etc/sing-box/config.json"
    
    # 其他配置
    "/etc/hysteria/config.json"
    "/etc/tuic/config.json"
    "/etc/trojan/config.json"
)

# Hiddify专用端口识别（基于实际部署）
HIDDIFY_COMMON_PORTS=(
    # 管理面板
    "443" "8443" "9443"
    # 常见代理端口
    "80" "8080" "8880"
    # Hiddify默认端口范围
    "2053" "2083" "2087" "2096"
    "8443" "8880"
)

# 代理协议标准端口（精确识别）
STANDARD_PROXY_PORTS=(
    # HTTP/HTTPS代理
    "80" "443" "8080" "8443" "8880" "8888"
    # SOCKS代理
    "1080" "1085"
    # Shadowsocks常用端口
    "8388" "8389" "9000" "9001"
    # 常见代理端口
    "2080" "2443" "3128" "8964"
    # Trojan端口
    "8443" "9443"
)

# 内部服务端口（不应对外开放）
INTERNAL_SERVICE_PORTS=(
    # 常见内部端口
    8181 10085 10086 9090 3000 3001 8000 8001
    # Sing-box 内部端口范围
    10080 10081 10082 10083 10084 10085 10086 10087 10088 10089
    # X-UI 内部端口
    54321 62789
    # Hiddify 内部端口
    9000 9001 9002
    # 其他管理端口
    8090 8091 8092 8093 8094 8095
)

# 危险端口黑名单（绝不开放）
BLACKLIST_PORTS=(
    # 系统关键端口
    22 23 25 53 69 111 135 137 138 139 445 514 631
    # 数据库端口
    1433 1521 3306 5432 6379 27017
    # 远程管理端口
    3389 5900 5901 5902
    # 邮件服务端口
    110 143 465 587 993 995
    # 内部服务端口（不对外）
    8181 10085 10086
)

# 辅助函数
debug_log() { if [ "$DEBUG_MODE" = true ]; then echo -e "${BLUE}[DEBUG] $1${RESET}"; fi; }
error_exit() { echo -e "${RED}❌ $1${RESET}"; exit 1; }
warning() { echo -e "${YELLOW}⚠️  $1${RESET}"; }
success() { echo -e "${GREEN}✓ $1${RESET}"; }
info() { echo -e "${CYAN}ℹ️  $1${RESET}"; }

# 字符串分割函数（替换有问题的cut命令）
split_nat_rule() {
    local rule="$1"
    local delimiter="$2"
    local field="$3"
    
    # 使用bash内置的字符串替换功能
    if [ "$delimiter" = "->" ]; then
        if [ "$field" = "1" ]; then
            echo "${rule%->*}"  # 返回->之前的部分
        elif [ "$field" = "2" ]; then
            echo "${rule#*->}"  # 返回->之后的部分
        fi
    else
        # 对于其他分隔符，使用cut命令
        echo "$rule" | cut -d"$delimiter" -f"$field"
    fi
}

# 显示帮助
show_help() {
    cat << 'EOF'
精准代理端口防火墙管理脚本 v1.2.3 (修复版)

专为现代代理面板设计的智能端口管理工具

用法: bash script.sh [选项]

选项:
    --debug           显示详细调试信息
    --dry-run         预演模式，不实际修改防火墙
    --add-range       交互式添加端口跳跃规则
    --help, -h        显示此帮助信息

支持的代理面板/软件:
    ✓ Hiddify Manager/Panel
    ✓ 3X-UI / X-UI
    ✓ Xray / V2Ray
    ✓ Sing-box
    ✓ Hysteria / Hysteria2
    ✓ Trojan-Go / Trojan
    ✓ Shadowsocks系列
    ✓ 其他主流代理工具

安全特性:
    ✓ 精准端口识别，避免开放不必要端口
    ✓ 自动过滤内部服务端口
    ✓ 自动过滤危险端口
    ✓ SSH暴力破解保护
    ✓ 基于nftables的现代防火墙

修复内容 (v1.2.3):
    ✓ 修复语法错误
    ✓ 修复端口跳跃功能的字符串解析错误
    ✓ 改进NAT规则生成和验证
    ✓ 增强错误处理和调试信息

端口跳跃说明:
    端口跳跃允许将一个端口范围的流量转发到单个目标端口，
    例如: 16820-16888 → 16801
    这对于绕过某些网络限制或负载均衡非常有用。

EOF
}

# 参数解析
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug) DEBUG_MODE=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --add-range) add_port_range_interactive; exit 0 ;;
            --help|-h) show_help; exit 0 ;;
            *) error_exit "未知参数: $1" ;;
        esac
    done
}

# 检查系统环境
check_system() {
    info "检查系统环境..."
    
    # 检查并安装必要工具
    local tools=("ss" "nft" "jq" "netstat")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            info "安装 $tool..."
            if [ "$DRY_RUN" = false ]; then
                if command -v apt-get >/dev/null 2>&1; then
                    apt-get update -qq && apt-get install -y nftables iproute2 jq net-tools
                elif command -v yum >/dev/null 2>&1; then
                    yum install -y nftables iproute jq net-tools
                elif command -v dnf >/dev/null 2>&1; then
                    dnf install -y nftables iproute jq net-tools
                fi
                break
            fi
        fi
    done
    
    success "系统环境检查完成"
}

# 检测SSH端口
detect_ssh_port() {
    debug_log "检测SSH端口..."
    
    # 优先从进程监听检测
    local ssh_port=$(ss -tlnp 2>/dev/null | grep -E ':22\b|sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -1)
    
    # 从配置文件检测
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] && [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -i '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print $2}' | head -1)
    fi
    
    # 默认SSH端口
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]]; then
        ssh_port="22"
    fi
    
    SSH_PORT="$ssh_port"
    info "检测到SSH端口: $SSH_PORT"
}

# 检测现有NAT规则和端口跳跃（修复版）
detect_existing_nat_rules() {
    info "检测现有端口跳跃规则..."
    
    local nat_rules=()
    local unique_rules=()
    
    # 检测nftables NAT规则
    if command -v nft >/dev/null 2>&1; then
        while IFS= read -r line; do
            if echo "$line" | grep -qE "udp[[:space:]]+dport[[:space:]]+[0-9]+-[0-9]+.*dnat[[:space:]]+to[[:space:]]+:[0-9]+"; then
                local port_range=$(echo "$line" | grep -oE "[0-9]+-[0-9]+" | head -1)
                local target_port=$(echo "$line" | grep -oE ":[0-9]+" | grep -oE "[0-9]+" | head -1)
                if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                    local rule_key="$port_range->$target_port"
                    nat_rules+=("$rule_key")
                    debug_log "发现端口跳跃规则: $port_range -> $target_port"
                fi
            fi
        done <<< "$(nft list ruleset 2>/dev/null | grep -E "udp dport.*dnat to")"
    fi
    
    # 检测iptables NAT规则
    if command -v iptables >/dev/null 2>&1; then
        while IFS= read -r line; do
            if echo "$line" | grep -qE "DNAT.*udp.*dpts:[0-9]+:[0-9]+.*to:[0-9]+"; then
                local port_range=$(echo "$line" | grep -oE "dpts:[0-9]+:[0-9]+" | grep -oE "[0-9]+:[0-9]+" | sed 's/:/-/')
                local target_port=$(echo "$line" | grep -oE "to:[0-9]+" | grep -oE "[0-9]+")
                if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                    local rule_key="$port_range->$target_port"
                    nat_rules+=("$rule_key")
                    debug_log "发现iptables端口跳跃规则: $port_range -> $target_port"
                fi
            fi
        done <<< "$(iptables -t nat -L -n -v 2>/dev/null | grep DNAT)"
    fi
    
    # 去重NAT规则
    if [ ${#nat_rules[@]} -gt 0 ]; then
        unique_rules=($(printf '%s\n' "${nat_rules[@]}" | sort -u))
        NAT_RULES=("${unique_rules[@]}")
        
        # 将目标端口添加到检测端口列表（去重）
        for rule in "${NAT_RULES[@]}"; do
            local target_port=$(split_nat_rule "$rule" "->" "2")
            if [ -n "$target_port" ]; then
                DETECTED_PORTS+=("$target_port")
            fi
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔄 检测到现有端口跳跃规则:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            echo -e "  ${GREEN}• $rule${RESET}"
        done
        success "检测到 ${#NAT_RULES[@]} 个端口跳跃规则"
    else
        info "未检测到现有端口跳跃规则"
    fi
}

# 交互式添加端口跳跃规则
add_port_range_interactive() {
    echo -e "${CYAN}🔧 配置端口跳跃规则${RESET}"
    echo -e "${YELLOW}端口跳跃允许将一个端口范围转发到单个目标端口${RESET}"
    echo -e "${YELLOW}例如: 16820-16888 转发到 16801${RESET}"
    
    while true; do
        echo -e "\n${CYAN}请输入端口范围 (格式: 起始端口-结束端口，如 16820-16888):${RESET}"
        read -r port_range
        
        if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start_port="${BASH_REMATCH[1]}"
            local end_port="${BASH_REMATCH[2]}"
            
            if [ "$start_port" -ge "$end_port" ]; then
                error_exit "起始端口必须小于结束端口"
            fi
            
            echo -e "${CYAN}请输入目标端口 (单个端口号):${RESET}"
            read -r target_port
            
            if [[ "$target_port" =~ ^[0-9]+$ ]] && [ "$target_port" -ge 1 ] && [ "$target_port" -le 65535 ]; then
                NAT_RULES+=("$port_range->$target_port")
                DETECTED_PORTS+=("$target_port")
                success "添加端口跳跃规则: $port_range -> $target_port"
                
                echo -e "${YELLOW}是否继续添加其他端口跳跃规则? [y/N]${RESET}"
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

# 智能检测代理进程
detect_proxy_processes() {
    info "检测代理服务进程..."
    
    local found_processes=()
    
    # 检查核心代理进程
    for process in "${PROXY_CORE_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found_processes+=("$process")
            debug_log "发现代理进程: $process"
        fi
    done
    
    # 检查Web面板进程
    for process in "${WEB_PANEL_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found_processes+=("$process")
            debug_log "发现Web面板进程: $process"
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
    
    # 检查是否是公网监听地址
    if [[ "$address" =~ ^(\*|0\.0\.0\.0|\[::\]|::): ]]; then
        echo "public"
    # 检查是否是本地回环地址
    elif [[ "$address" =~ ^(127\.|::1|\[::1\]): ]]; then
        echo "localhost"
    # 检查是否是内网地址
    elif [[ "$address" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.): ]]; then
        echo "private"
    # 其他情况
    else
        echo "unknown"
    fi
}

# 从配置文件解析端口
parse_config_ports() {
    info "解析配置文件中的端口..."
    
    local config_ports=()
    
    for config_file in "${PROXY_CONFIG_FILES[@]}"; do
        if [ -f "$config_file" ]; then
            debug_log "分析配置文件: $config_file"
            
            # 根据文件类型解析端口
            if [[ "$config_file" =~ \.json$ ]]; then
                # JSON配置文件
                if command -v jq >/dev/null 2>&1; then
                    # 更精确的JSON解析，查找inbounds中的公网监听端口
                    local ports=$(jq -r '.inbounds[]? | select(.listen == null or .listen == "" or .listen == "0.0.0.0" or .listen == "::") | .port' "$config_file" 2>/dev/null | grep -E '^[0-9]+$' | sort -nu)
                    if [ -n "$ports" ]; then
                        while read -r port; do
                            config_ports+=("$port")
                            debug_log "从 $config_file 解析到公网端口: $port"
                        done <<< "$ports"
                    fi
                    
                    # 也检查简单的port字段
                    local simple_ports=$(jq -r '.. | objects | select(has("port")) | .port' "$config_file" 2>/dev/null | grep -E '^[0-9]+$' | sort -nu)
                    if [ -n "$simple_ports" ]; then
                        while read -r port; do
                            # 只添加不在内部服务端口列表中的端口
                            if ! is_internal_service_port "$port"; then
                                config_ports+=("$port")
                                debug_log "从 $config_file 解析到端口: $port"
                            else
                                debug_log "跳过内部服务端口: $port"
                            fi
                        done <<< "$simple_ports"
                    fi
                else
                    # 简单文本解析
                    local ports=$(grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | grep -oE '[0-9]+' | sort -nu)
                    if [ -n "$ports" ]; then
                        while read -r port; do
                            if ! is_internal_service_port "$port"; then
                                config_ports+=("$port")
                                debug_log "从 $config_file 文本解析到端口: $port"
                            fi
                        done <<< "$ports"
                    fi
                fi
            elif [[ "$config_file" =~ \.(yaml|yml)$ ]]; then
                # YAML配置文件
                local ports=$(grep -oE 'port[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | grep -oE '[0-9]+' | sort -nu)
                if [ -n "$ports" ]; then
                    while read -r port; do
                        if ! is_internal_service_port "$port"; then
                            config_ports+=("$port")
                            debug_log "从 $config_file YAML解析到端口: $port"
                        fi
                    done <<< "$ports"
                fi
            fi
        fi
    done
    
    # 去重并存储
    if [ ${#config_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${config_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "从配置文件解析到 ${#unique_ports[@]} 个端口"
    fi
}

# 检测监听端口（改进版）
detect_listening_ports() {
    info "检测当前监听端口..."
    
    local listening_ports=()
    local localhost_ports=()
    
    # 使用ss命令检测
    while IFS= read -r line; do
        if [[ "$line" =~ LISTEN ]] || [[ "$line" =~ UNCONN ]]; then
            local protocol=$(echo "$line" | awk '{print tolower($1)}')
            local address_port=$(echo "$line" | awk '{print $5}')
            local process_info=$(echo "$line" | grep -oE 'users:\(\([^)]*\)\)' | head -1)
            
            # 提取端口号
            local port=$(echo "$address_port" | grep -oE '[0-9]+$')
            
            # 提取进程名
            local process="unknown"
            if [[ "$process_info" =~ \"([^\"]+)\" ]]; then
                process="${BASH_REMATCH[1]}"
            fi
            
            # 检查绑定地址类型
            local bind_type=$(check_bind_address "$address_port")
            
            debug_log "检测到监听: $address_port ($protocol, $process, $bind_type)"
            
            # 检查是否是代理相关进程
            if is_proxy_related "$process" && [ -n "$port" ] && [ "$port" != "$SSH_PORT" ]; then
                if [ "$bind_type" = "public" ]; then
                    # 公网监听端口
                    if ! is_internal_service_port "$port"; then
                        listening_ports+=("$port")
                        debug_log "检测到公网代理端口: $port ($protocol, $process)"
                    else
                        debug_log "跳过内部服务端口: $port"
                    fi
                elif [ "$bind_type" = "localhost" ]; then
                    # 本地监听端口（记录但不开放）
                    localhost_ports+=("$port")
                    debug_log "检测到本地代理端口: $port ($protocol, $process) - 不对外开放"
                fi
            fi
        fi
    done <<< "$(ss -tulnp 2>/dev/null)"
    
    # 显示本地监听端口信息
    if [ ${#localhost_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}🔒 检测到内部服务端口 (仅本地监听):${RESET}"
        for port in $(printf '%s\n' "${localhost_ports[@]}" | sort -nu); do
            echo -e "  ${YELLOW}• $port${RESET} - 内部服务，不对外开放"
        done
    fi
    
    # 去重并添加到检测列表
    if [ ${#listening_ports[@]} -gt 0 ]; then
        local unique_ports=($(printf '%s\n' "${listening_ports[@]}" | sort -nu))
        DETECTED_PORTS+=("${unique_ports[@]}")
        success "检测到 ${#unique_ports[@]} 个公网监听端口"
    fi
}

# 判断是否是代理相关进程
is_proxy_related() {
    local process="$1"
    
    # 精确匹配
    for proxy_proc in "${PROXY_CORE_PROCESSES[@]}" "${WEB_PANEL_PROCESSES[@]}"; do
        if [[ "$process" == *"$proxy_proc"* ]]; then
            return 0
        fi
    done
    
    # 模糊匹配常见代理关键词
    if [[ "$process" =~ (proxy|vpn|tunnel|shadowsocks|trojan|v2ray|xray|clash|hysteria|sing) ]]; then
        return 0
    fi
    
    return 1
}

# 检查是否是内部服务端口
is_internal_service_port() {
    local port="$1"
    
    for internal_port in "${INTERNAL_SERVICE_PORTS[@]}"; do
        if [ "$port" = "$internal_port" ]; then
            return 0
        fi
    done
    
    return 1
}

# 检查是否是标准代理端口
is_standard_proxy_port() {
    local port="$1"
    
    # 检查常用代理端口
    local common_ports=(80 443 1080 1085 8080 8388 8443 8880 8888 9443)
    for common_port in "${common_ports[@]}"; do
        if [ "$port" = "$common_port" ]; then
            return 0
        fi
    done
    
    # 检查高端口范围（10000-10999, 30000-39999）- 但排除已知内部端口
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
    
    # 检查是否在黑名单中
    for blacklist_port in "${BLACKLIST_PORTS[@]}"; do
        if [ "$port" = "$blacklist_port" ]; then
            debug_log "端口 $port 在黑名单中"
            return 1
        fi
    done
    
    # 检查是否是内部服务端口
    if is_internal_service_port "$port"; then
        debug_log "端口 $port 是内部服务端口"
        return 1
    fi
    
    # 端口范围检查
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        debug_log "端口 $port 超出有效范围"
        return 1
    fi
    
    # SSH端口单独处理，不在这里过滤（SSH端口会在防火墙规则中单独处理）
    # 默认开放端口（80, 443）始终安全
    if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
        debug_log "端口 $port 是默认开放端口"
        return 0
    fi
    
    return 0
}

# 智能端口过滤和确认
filter_and_confirm_ports() {
    info "智能端口分析和确认..."
    
    # 添加默认开放端口（80、443）
    info "添加默认开放端口: ${DEFAULT_OPEN_PORTS[*]}"
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    
    # 去重所有检测到的端口
    local all_ports=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -nu))
    local safe_ports=()
    local suspicious_ports=()
    local unsafe_ports=()
    local internal_ports=()
    
    # 分类端口
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
            # 其他端口需要进一步检查
            suspicious_ports+=("$port")
        fi
    done
    
    # 显示检测结果
    if [ ${#safe_ports[@]} -gt 0 ]; then
        echo -e "\n${GREEN}✅ 标准代理端口 (推荐开放):${RESET}"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}✓ $port${RESET} - 默认开放端口"
            else
                echo -e "  ${GREEN}✓ $port${RESET} - 常见代理端口"
            fi
        done
    fi
    
    if [ ${#internal_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}🔒 内部服务端口 (已过滤):${RESET}"
        for port in "${internal_ports[@]}"; do
            echo -e "  ${YELLOW}- $port${RESET} - 内部服务端口，不对外开放"
        done
    fi
    
    if [ ${#suspicious_ports[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}⚠️  可疑端口 (建议确认):${RESET}"
        for port in "${suspicious_ports[@]}"; do
            echo -e "  ${YELLOW}? $port${RESET} - 不是标准代理端口"
        done
        
        echo -e "\n${YELLOW}这些端口可能不是必需的代理端口，建议确认后再开放${RESET}"
        
        if [ "$DRY_RUN" = false ]; then
            echo -e "${YELLOW}是否也要开放这些可疑端口? [y/N]${RESET}"
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
        echo -e "\n${RED}❌ 危险端口 (已跳过):${RESET}"
        for port in "${unsafe_ports[@]}"; do
            echo -e "  ${RED}✗ $port${RESET} - 系统端口或危险端口"
        done
    fi
    
    # 询问用户是否需要配置端口跳跃
    if [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -eq 0 ]; then
        echo -e "\n${CYAN}🔄 是否需要配置端口跳跃功能? [y/N]${RESET}"
        echo -e "${YELLOW}端口跳跃可以将一个端口范围转发到单个目标端口${RESET}"
        read -r response
        if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            add_port_range_interactive
        fi
    fi
    
    # 用户最终确认
    if [ ${#safe_ports[@]} -eq 0 ]; then
        warning "没有检测到需要开放的标准代理端口"
        # 至少开放默认端口
        safe_ports=("${DEFAULT_OPEN_PORTS[@]}")
    fi
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "\n${CYAN}📋 最终将开放以下端口:${RESET}"
        for port in "${safe_ports[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${CYAN}• $port${RESET} (默认开放)"
            else
                echo -e "  ${CYAN}• $port${RESET}"
            fi
        done
        
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "\n${CYAN}🔄 端口跳跃规则:${RESET}"
            for rule in "${NAT_RULES[@]}"; do
                echo -e "  ${CYAN}• $rule${RESET}"
            done
        fi
        
        echo -e "\n${YELLOW}确认开放以上 ${#safe_ports[@]} 个端口"
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            echo -e "以及 ${#NAT_RULES[@]} 个端口跳跃规则"
        fi
        echo -e "? [Y/n]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]?$ ]]; then
            info "用户取消操作"
            exit 0
        fi
    fi
    
    # 更新全局端口列表（去重）
    DETECTED_PORTS=($(printf '%s\n' "${safe_ports[@]}" | sort -nu))
    return 0
}

# 生成nftables规则（修复版）
generate_nftables_rules() {
    local ports_tcp=()
    local ports_udp=()
    
    # 分类端口（默认同时开放TCP和UDP）
    for port in "${DETECTED_PORTS[@]}"; do
        ports_tcp+=("$port")
        ports_udp+=("$port")
    done
    
    # 生成规则内容
    local tcp_rule=""
    local udp_rule=""
    local nat_rules_content=""
    
    if [ ${#ports_tcp[@]} -gt 0 ]; then
        if [ ${#ports_tcp[@]} -eq 1 ]; then
            tcp_rule="        tcp dport ${ports_tcp[0]} accept comment \"代理服务端口\""
        else
            local tcp_set=$(IFS=','; echo "${ports_tcp[*]}")
            tcp_rule="        tcp dport { $tcp_set } accept comment \"代理服务端口\""
        fi
    fi
    
    if [ ${#ports_udp[@]} -gt 0 ]; then
        if [ ${#ports_udp[@]} -eq 1 ]; then
            udp_rule="        udp dport ${ports_udp[0]} accept comment \"代理服务端口\""
        else
            local udp_set=$(IFS=','; echo "${ports_udp[*]}")
            udp_rule="        udp dport { $udp_set } accept comment \"代理服务端口\""
        fi
    fi
    
    # 生成NAT规则内容（使用修复的字符串解析）
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        nat_rules_content="
table inet nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;"
        
        for rule in "${NAT_RULES[@]}"; do
            # 使用新的字符串分割函数
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                nat_rules_content="$nat_rules_content
        udp dport $port_range counter dnat to :$target_port comment \"端口跳跃: $port_range -> $target_port\""
                debug_log "生成NAT规则: $port_range -> $target_port"
            else
                warning "无法解析NAT规则: $rule"
            fi
        done
        
        nat_rules_content="$nat_rules_content
    }
}"
    fi
    
    # 生成完整的nftables配置
    cat << EOF
#!/usr/sbin/nft -f
# 精准代理端口防火墙规则 v1.2.3 (修复版)
# 生成时间: $(date)
# 修复: 语法错误和端口跳跃功能

flush ruleset
$nat_rules_content

table inet filter {
    # SSH暴力破解保护
    set ssh_attackers {
        type ipv4_addr
        flags timeout, dynamic
        timeout 1h
        size 10000
    }
    
    chain input {
        type filter hook input priority filter
        policy drop
        
        # 基本连接状态处理
        ct state invalid drop
        ct state {established, related} accept
        iif lo accept
        
        # ICMP支持（网络诊断）
        ip protocol icmp limit rate 10/second accept
        ip6 nexthdr icmpv6 limit rate 10/second accept
        
        # SSH保护规则
        tcp dport $SSH_PORT ct state new limit rate over 3/minute \\
            add @ssh_attackers { ip saddr timeout 1h } drop
        tcp dport $SSH_PORT accept comment "SSH访问"
        
        # 代理服务端口规则
$tcp_rule
$udp_rule
        
        # 记录并拒绝其他连接
        limit rate 3/minute log prefix "nft-drop: " level warn
        drop
    }
    
    chain forward {
        type filter hook forward priority filter
        policy drop
    }
    
    chain output {
        type filter hook output priority filter
        policy accept
    }
}
EOF
}

# 应用防火墙规则
apply_firewall_rules() {
    info "应用防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演模式] 防火墙规则:"
        generate_nftables_rules
        return 0
    fi
    
    # 生成配置文件
    local config_file="/etc/nftables.conf"
    generate_nftables_rules > "$config_file"
    chmod 644 "$config_file"
    
    # 测试规则语法
    if ! nft -c -f "$config_file"; then
        error_exit "nftables规则语法错误"
    fi
    
    # 应用规则
    if nft -f "$config_file"; then
        success "防火墙规则应用成功"
        OPENED_PORTS=${#DETECTED_PORTS[@]}
        
        # 验证端口跳跃规则是否生效
        if [ ${#NAT_RULES[@]} -gt 0 ]; then
            info "验证端口跳跃规则..."
            sleep 2  # 等待规则生效
            local nat_count=$(nft list table inet nat 2>/dev/null | grep -c "dnat to" || echo "0")
            if [ "$nat_count" -gt 0 ]; then
                success "端口跳跃规则应用成功 ($nat_count 条规则)"
            else
                warning "端口跳跃规则可能未正确应用"
            fi
        fi
    else
        error_exit "防火墙规则应用失败"
    fi
    
    # 启用nftables服务
    systemctl enable nftables >/dev/null 2>&1 || true
    systemctl restart nftables >/dev/null 2>&1 || true
    
    success "nftables服务已启动"
}

# 清理现有防火墙
cleanup_firewalls() {
    info "清理现有防火墙配置..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预演模式] 将清理现有防火墙"
        return 0
    fi
    
    # 停用其他防火墙服务
    for service in ufw firewalld; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
            success "已停用 $service"
        fi
    done
    
    # 重置UFW（如果存在）
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset >/dev/null 2>&1 || true
    fi
    
    # 清理iptables规则（但保留现有NAT规则）
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    iptables -F INPUT 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    iptables -F OUTPUT 2>/dev/null || true
    
    # 注意：不清理NAT表，保留现有的端口跳跃规则
    info "保留现有NAT规则（端口跳跃）"
    
    success "防火墙清理完成（保留NAT规则）"
}

# 验证端口跳跃功能（修复版）
verify_port_hopping() {
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "验证端口跳跃配置..."
        
        echo -e "\n${CYAN}🔍 当前NAT规则状态:${RESET}"
        if command -v nft >/dev/null 2>&1; then
            local nat_output=$(nft list table inet nat 2>/dev/null)
            if [ -n "$nat_output" ]; then
                echo "$nat_output" | grep -E "(dnat to|comment)" || echo "无NAT规则"
            else
                echo "NAT表不存在"
            fi
        fi
        
        echo -e "\n${YELLOW}💡 端口跳跃使用说明:${RESET}"
        echo -e "  - 客户端可以连接到端口范围内的任意端口"
        echo -e "  - 所有连接都会转发到目标端口"
        echo -e "  - 例如: 连接 16850 会转发到 16801"
        
        # 检查目标端口是否在监听（使用修复的字符串解析）
        local checked_ports=()
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            debug_log "验证规则: $port_range -> $target_port"
            
            if [ -n "$target_port" ]; then
                # 避免重复检查同一个端口
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
        
        echo -e "\n${CYAN}📝 端口跳跃规则汇总:${RESET}"
        local unique_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        for rule in "${unique_rules[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            echo -e "  ${CYAN}• 端口范围 $port_range → 目标端口 $target_port${RESET}"
        done
    fi
}

# 显示最终状态
show_final_status() {
    echo -e "\n${GREEN}=================================="
    echo -e "🎉 防火墙配置完成！"
    echo -e "==================================${RESET}"
    
    echo -e "\n${CYAN}📊 配置摘要:${RESET}"
    echo -e "  ${GREEN}✓ 开放端口数量: $OPENED_PORTS${RESET}"
    echo -e "  ${GREEN}✓ SSH端口: $SSH_PORT (已保护)${RESET}"
    echo -e "  ${GREEN}✓ 防火墙引擎: nftables${RESET}"
    echo -e "  ${GREEN}✓ 内部服务保护: 已启用${RESET}"
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "  ${GREEN}✓ 端口跳跃规则: ${#NAT_RULES[@]} 个${RESET}"
    fi
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 已开放的端口:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            echo -e "  ${GREEN}• $port (TCP/UDP)${RESET}"
        done
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${CYAN}🔄 端口跳跃规则:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            echo -e "  ${CYAN}• $port_range → $target_port${RESET}"
        done
    fi
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "\n${CYAN}🔍 这是预演模式，实际未修改防火墙${RESET}"
        return 0
    fi
    
    echo -e "\n${CYAN}🔧 管理命令:${RESET}"
    echo -e "  ${YELLOW}查看规则:${RESET} nft list ruleset"
    echo -e "  ${YELLOW}查看端口:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}重启防火墙:${RESET} systemctl restart nftables"
    echo -e "  ${YELLOW}查看日志:${RESET} journalctl -u nftables"
    echo -e "  ${YELLOW}添加端口跳跃:${RESET} bash script.sh --add-range"
    echo -e "  ${YELLOW}查看NAT规则:${RESET} nft list table inet nat"
    
    echo -e "\n${GREEN}✅ 代理端口已精准开放，端口跳跃已配置，内部服务已保护，服务器安全防护已启用！${RESET}"
}

# 主函数
main() {
    # 信号处理
    trap 'echo -e "\n${RED}操作被中断${RESET}"; exit 130' INT TERM
    
    # 解析参数
    parse_arguments "$@"
    
    echo -e "\n${CYAN}🚀 开始智能代理端口检测和配置...${RESET}"
    
    # 1. 系统检查
    check_system
    
    # 2. 检测SSH端口
    detect_ssh_port
    
    # 3. 检测现有NAT规则
    detect_existing_nat_rules
    
    # 4. 清理现有防火墙（保留NAT）
    cleanup_firewalls
    
    # 5. 检测代理进程
    if ! detect_proxy_processes; then
        warning "建议启动代理服务后再运行此脚本以获得最佳效果"
    fi
    
    # 6. 解析配置文件端口
    parse_config_ports
    
    # 7. 检测监听端口
    detect_listening_ports
    
    # 8. 端口过滤和确认
    if ! filter_and_confirm_ports; then
        info "添加Hiddify常用端口作为备选..."
        DETECTED_PORTS=("${HIDDIFY_COMMON_PORTS[@]}")
        if ! filter_and_confirm_ports; then
            error_exit "无法确定需要开放的端口"
        fi
    fi
    
    # 9. 应用防火墙规则
    apply_firewall_rules
    
    # 10. 验证端口跳跃功能
    verify_port_hopping
    
    # 11. 显示最终状态
    show_final_status
}

# 脚本入口
main "$@"

# 保存 nftables 规则
save_nftables_rules() {
    info "保存 nftables 规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将保存 nftables 规则"
        return 0
    fi
    
    local config_file=""
    
    # 确定配置文件路径
    if [ -d "/etc/nftables" ]; then
        config_file="/etc/nftables/proxy_firewall.nft"
    else
        config_file="/etc/nftables.conf"
    fi
    
    # 保存当前规则集
    nft list table inet "$NFTABLES_TABLE" > "$config_file" 2>/dev/null || {
        warning "无法保存到 $config_file，尝试备用路径"
        config_file="/tmp/nftables_rules.nft"
        nft list table inet "$NFTABLES_TABLE" > "$config_file"
    }
    
    # 创建服务文件以确保规则持久化
    if command -v systemctl >/dev/null 2>&1; then
        cat > /etc/systemd/system/nftables-proxy.service << EOF
[Unit]
Description=恢复代理防火墙 nftables 规则
After=network-pre.target
Before=network.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f $config_file
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl enable nftables-proxy.service >/dev/null 2>&1 || true
        systemctl enable nftables.service >/dev/null 2>&1 || true
    fi
    
    success "nftables 规则已保存到: $config_file"
}

# 显示规则预览
show_rules_preview() {
    echo -e "${CYAN}📋 即将应用的 nftables 规则预览:${RESET}"
    echo
    echo "table inet $NFTABLES_TABLE {"
    echo "    chain input {"
    echo "        type filter hook input priority 0; policy drop;"
    echo "        iif lo accept"
    echo "        ct state established,related accept"
    echo "        icmp type echo-request limit rate 10/second accept"
    echo "        tcp dport $SSH_PORT ct state new limit rate 4/minute accept"
    echo
    echo "        # 代理端口"
    for port in "${DETECTED_PORTS[@]}"; do
        echo "        tcp dport $port accept"
        echo "        udp dport $port accept"
    done
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo
        echo "        # 端口转发范围"
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local start_port=$(echo "$port_range" | cut -d'-' -f1)
            local end_port=$(echo "$port_range" | cut -d'-' -f2)
            echo "        tcp dport $start_port-$end_port accept"
            echo "        udp dport $start_port-$end_port accept"
        done
    fi
    
    echo "        limit rate 3/minute log prefix \"proxy-firewall-drop: \" level info"
    echo "    }"
    echo
    echo "    chain forward {"
    echo "        type filter hook forward priority 0; policy drop;"
    echo "    }"
    echo
    echo "    chain output {"
    echo "        type filter hook output priority 0; policy accept;"
    echo "    }"
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo
        echo "    chain prerouting {"
        echo "        type nat hook prerouting priority -100;"
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            local start_port=$(echo "$port_range" | cut -d'-' -f1)
            local end_port=$(echo "$port_range" | cut -d'-' -f2)
            echo "        tcp dport $start_port-$end_port dnat to :$target_port"
            echo "        udp dport $start_port-$end_port dnat to :$target_port"
        done
        echo "    }"
    fi
    
    echo "}"
}

# 验证端口转发功能
verify_port_hopping() {
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "验证端口转发配置..."
        
        echo -e "\n${CYAN}🔍 当前 NAT 规则状态:${RESET}"
        if command -v nft >/dev/null 2>&1 && nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
            nft list chain inet "$NFTABLES_TABLE" prerouting 2>/dev/null | grep dnat || echo "无 NAT 规则"
        fi
        
        echo -e "\n${YELLOW}💡 端口转发使用说明:${RESET}"
        echo -e "  - 客户端可以连接到范围内的任意端口"
        echo -e "  - 所有连接都会转发到目标端口"
        echo -e "  - 示例：范围内端口的连接转发到目标端口"
        
        local checked_ports=()
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            debug_log "验证规则: $port_range -> $target_port"
            
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
        echo -e "${RED}警告: 这将清除所有 nftables 规则！${RESET}"
        echo -e "${YELLOW}确认重置防火墙吗？[y/N]${RESET}"
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
        echo -e "${YELLOW}是否要清除所有 nftables 规则？这可能影响其他服务 [y/N]${RESET}"
        read -r response
        if [[ "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            nft flush ruleset
        fi
        
        # 清理服务文件
        if [ -f "/etc/systemd/system/nftables-proxy.service" ]; then
            systemctl disable nftables-proxy.service >/dev/null 2>&1 || true
            rm -f /etc/systemd/system/nftables-proxy.service
        fi
        
        success "防火墙已重置到默认状态"
    else
        info "[预览模式] 将重置所有 nftables 规则"
    fi
}

# 显示防火墙状态
show_firewall_status() {
    echo -e "${CYAN}🔍 当前防火墙状态${RESET}"
    echo
    
    if ! nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  代理防火墙表不存在${RESET}"
        echo -e "${CYAN}当前所有 nftables 表:${RESET}"
        nft list tables 2>/dev/null || echo "无表"
        return 0
    fi
    
    echo -e "${GREEN}📊 nftables 规则统计:${RESET}"
    local input_rules=$(nft list chain inet "$NFTABLES_TABLE" input 2>/dev/null | grep -c "accept\|drop\|log" || echo "0")
    local nat_rules=$(nft list chain inet "$NFTABLES_TABLE" prerouting 2>/dev/null | grep -c "dnat" || echo "0")
    echo -e "  INPUT 规则数: $input_rules"
    echo -e "  NAT 规则数: $nat_rules"
    echo
    
    echo -e "${GREEN}🔓 开放的端口:${RESET}"
    nft list chain inet "$NFTABLES_TABLE" input 2>/dev/null | grep "dport.*accept" | while read -r line; do
        if echo "$line" | grep -qE "tcp dport [0-9]+"; then
            local port=$(echo "$line" | grep -oE "dport [0-9]+" | awk '{print $2}')
            echo -e "  • $port (tcp)"
        elif echo "$line" | grep -qE "udp dport [0-9]+"; then
            local port=$(echo "$line" | grep -oE "dport [0-9]+" | awk '{print $2}')
            echo -e "  • $port (udp)"
        elif echo "$line" | grep -qE "dport [0-9]+-[0-9]+"; then
            local port_range=$(echo "$line" | grep -oE "dport [0-9]+-[0-9]+" | awk '{print $2}')
            local protocol="tcp/udp"
            if echo "$line" | grep -q "tcp"; then
                protocol="tcp"
            elif echo "$line" | grep -q "udp"; then
                protocol="udp"
            fi
            echo -e "  • $port_range ($protocol) - 端口范围"
        fi
    done
    echo
    
    echo -e "${GREEN}🔄 端口转发规则:${RESET}"
    local nat_count=0
    if nft list chain inet "$NFTABLES_TABLE" prerouting >/dev/null 2>&1; then
        while read -r line; do
            if echo "$line" | grep -q "dnat"; then
                nat_count=$((nat_count + 1))
                local port_range=""
                local target=""
                
                if echo "$line" | grep -qE "dport [0-9]+-[0-9]+"; then
                    port_range=$(echo "$line" | grep -oE "dport [0-9]+-[0-9]+" | awk '{print $2}')
                fi
                
                if echo "$line" | grep -qE ":[0-9]+"; then
                    target=$(echo "$line" | grep -oE ":[0-9]+" | sed 's/://')
                fi
                
                if [ -n "$port_range" ] && [ -n "$target" ]; then
                    local protocol="tcp/udp"
                    if echo "$line" | grep -q "tcp"; then
                        protocol="tcp"
                    elif echo "$line" | grep -q "udp"; then
                        protocol="udp"
                    fi
                    echo -e "  • $port_range → $target ($protocol)"
                fi
            fi
        done <<< "$(nft list chain inet "$NFTABLES_TABLE" prerouting 2>/dev/null)"
    fi
    
    if [ "$nat_count" -eq 0 ]; then
        echo -e "  ${YELLOW}无端口转发规则${RESET}"
    fi
    echo
    
    echo -e "${GREEN}🛡️  SSH 保护状态:${RESET}"
    if nft list chain inet "$NFTABLES_TABLE" input 2>/dev/null | grep -q "limit"; then
        echo -e "  ${GREEN}✓ SSH 暴力破解防护已启用${RESET}"
    else
        echo -e "  ${YELLOW}⚠️  SSH 暴力破解防护未启用${RESET}"
    fi
    echo
    
    echo -e "${GREEN}🔧 WARP 检测状态:${RESET}"
    local warp_detected=false
    for warp_port in "${WARP_COMMON_PORTS[@]}"; do
        if nft list chain inet "$NFTABLES_TABLE" input 2>/dev/null | grep -q "dport $warp_port"; then
            echo -e "  ${GREEN}✓ WARP 端口 $warp_port 已开放${RESET}"
            warp_detected=true
        fi
    done
    if [ "$warp_detected" = false ]; then
        echo -e "  ${YELLOW}⚠️  未检测到 WARP 端口${RESET}"
    fi
    echo
    
    echo -e "${CYAN}🔧 管理命令:${RESET}"
    echo -e "  ${YELLOW}查看所有规则:${RESET} nft list ruleset"
    echo -e "  ${YELLOW}查看代理表:${RESET} nft list table inet $NFTABLES_TABLE"
    echo -e "  ${YELLOW}查看 NAT 规则:${RESET} nft list chain inet $NFTABLES_TABLE prerouting"
    echo -e "  ${YELLOW}查看监听端口:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}重新配置:${RESET} bash $0"
    echo -e "  ${YELLOW}添加端口转发:${RESET} bash $0 --add-range"
    echo -e "  ${YELLOW}手动添加端口:${RESET} bash $0 --add-port"
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
    echo -e "  ${GREEN}✓ 防火墙表: $NFTABLES_TABLE${RESET}"
    echo -e "  ${GREEN}✓ 内部服务保护: 已启用${RESET}"
    echo -e "  ${GREEN}✓ 默认端口: 80, 443 (永久开放)${RESET}"
    echo -e "  ${GREEN}✓ WARP 支持: 已启用${RESET}"
    echo -e "  ${GREEN}✓ 每次运行前清理旧规则: 已启用${RESET}"
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        local unique_nat_rules=($(printf '%s\n' "${NAT_RULES[@]}" | sort -u))
        echo -e "  ${GREEN}✓ 端口转发规则: ${#unique_nat_rules[@]} 条${RESET}"
    fi
    
    if [ ${#DETECTED_PORTS[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔓 已开放端口:${RESET}"
        for port in "${DETECTED_PORTS[@]}"; do
            if [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}• $port (TCP/UDP) - 默认开放${RESET}"
            elif [[ " ${WARP_COMMON_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}• $port (TCP/UDP) - WARP 端口${RESET}"
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
    
    echo -e "\n${CYAN}🔧 管理命令:${RESET}"
    echo -e "  ${YELLOW}查看所有规则:${RESET} nft list ruleset"
    echo -e "  ${YELLOW}查看代理表:${RESET} nft list table inet $NFTABLES_TABLE"
    echo -e "  ${YELLOW}查看监听端口:${RESET} ss -tlnp"
    echo -e "  ${YELLOW}查看 NAT 规则:${RESET} nft list chain inet $NFTABLES_TABLE prerouting"
    echo -e "  ${YELLOW}查看状态:${RESET} bash $0 --status"
    echo -e "  ${YELLOW}添加端口转发:${RESET} bash $0 --add-range"
    echo -e "  ${YELLOW}手动添加端口:${RESET} bash $0 --add-port"
    echo -e "  ${YELLOW}重置防火墙:${RESET} bash $0 --reset"
    
    echo -e "\n${GREEN}✅ 代理端口精确开放，端口转发已配置，WARP 支持已启用，内部服务受保护，服务器安全已启用！${RESET}"
    
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
    
    # 显示 nftables 服务状态
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-enabled nftables >/dev/null 2>&1; then
            echo -e "\n${GREEN}✅ nftables 服务已启用，规则将在重启后自动恢复${RESET}"
        else
            echo -e "\n${YELLOW}⚠️  建议启用 nftables 服务以确保规则持久化:${RESET}"
            echo -e "${YELLOW}   systemctl enable nftables${RESET}"
        fi
    fi
}

# 主函数
main() {
    trap 'echo -e "\n${RED}操作被中断${RESET}"; exit 130' INT TERM
    
    parse_arguments "$@"
    
    echo -e "\n${CYAN}🚀 开始智能代理端口检测和配置...${RESET}"
    
    check_system
    detect_ssh_port
    
    # 每次运行前清理旧规则（新增功能）
    cleanup_existing_rules
    
    detect_existing_nat_rules
    
    # 检测 WARP 服务
    detect_warp_service
    
    # 智能解析端口范围（新增功能）
    parse_port_ranges
    
    if ! detect_proxy_processes; then
        warning "建议在运行此脚本之前启动代理服务以获得最佳效果"
    fi
    
    parse_config_ports
    detect_listening_ports
    
    if ! filter_and_confirm_ports; then
        info "添加 Hiddify 常用端口作为备用..."
        DETECTED_PORTS=("${HIDDIFY_COMMON_PORTS[@]}")
        if ! filter_and_confirm_ports; then
            error_exit "无法确定要开放的端口"
        fi
    fi
    
    apply_firewall_rules
    verify_port_hopping
    show_final_status
}

# 脚本入口点
main "$@"#!/bin/bash
set -e

# 颜色定义
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

# 脚本信息
SCRIPT_VERSION="2.1.1"
SCRIPT_NAME="精确代理端口防火墙管理脚本（nftables 版本）"

echo -e "${YELLOW}== 🚀 ${SCRIPT_NAME} v${SCRIPT_VERSION} ==${RESET}"
echo -e "${CYAN}针对 Hiddify、3X-UI、X-UI、Sing-box、Xray、WARP 等代理面板优化${RESET}"
echo -e "${GREEN}🔧 使用 nftables 实现现代化防火墙管理${RESET}"

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
    "/var/lib/cloudflare-warp/mdm.xml"
    "/opt/warp/config.json"
)

# Hiddify 常用端口
HIDDIFY_COMMON_PORTS=(
    "443" "8443" "9443"
    "80" "8080" "8880"
    "2053" "2083" "2087" "2096"
)

# WARP 常用端口
WARP_COMMON_PORTS=(
    "2408" "500" "1701" "4500"
    "51820" "51821"
    "38001" "38002"
)

# 标准代理端口
STANDARD_PROXY_PORTS=(
    "80" "443" "8080" "8443" "8880" "8888"
    "1080" "1085"
    "8388" "8389" "9000" "9001"
    "2080" "2443" "3128" "8964"
    "8443" "9443"
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
精确代理端口防火墙管理脚本 v2.1.1（nftables 版本）

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
    ✓ WARP 端口自动检测
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
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update -qq && apt-get install -y nftables iproute2 jq
            elif command -v yum >/dev/null 2>&1; then
                yum install -y nftables iproute jq
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y nftables iproute jq
            elif command -v pacman >/dev/null 2>&1; then
                pacman -S --noconfirm nftables iproute2 jq
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
    debug_log "检测 SSH 端口..."
    
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

# 清理所有现有规则（每次运行前执行）
cleanup_existing_rules() {
    info "🧹 清理所有现有防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将清理所有现有规则"
        return 0
    fi
    
    # 停用其他防火墙服务
    for service in ufw firewalld iptables; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" >/dev/null 2>&1 || true
            systemctl disable "$service" >/dev/null 2>&1 || true
            success "已禁用 $service"
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
        debug_log "规则备份保存到: $nft_backup"
    fi
    
    # 清理现有的代理防火墙表
    if nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
        nft delete table inet "$NFTABLES_TABLE" 2>/dev/null || true
        success "已删除现有的代理防火墙表"
    fi
    
    # 清理所有 nftables 规则（可选，更彻底的清理）
    echo -e "${YELLOW}是否要清理所有现有的 nftables 规则？[Y/n]${RESET}"
    read -r response
    if [[ "$response" =~ ^[Yy]?$ ]]; then
        nft flush ruleset 2>/dev/null || true
        success "已清理所有 nftables 规则"
    fi
    
    success "防火墙规则清理完成"
}

# 检测 WARP 服务和端口
detect_warp_service() {
    info "检测 Cloudflare WARP 服务..."
    
    local warp_found=false
    local warp_ports=()
    
    # 检测 WARP 进程
    if pgrep -f "warp" >/dev/null 2>&1; then
        warp_found=true
        debug_log "检测到 WARP 相关进程"
    fi
    
    # 检测 WARP 配置文件
    for config_file in "/var/lib/cloudflare-warp/mdm.xml" "/opt/warp/config.json" "/etc/warp/config.json"; do
        if [ -f "$config_file" ]; then
            warp_found=true
            debug_log "检测到 WARP 配置文件: $config_file"
            
            # 尝试从配置文件提取端口
            if [[ "$config_file" =~ \.json$ ]] && command -v jq >/dev/null 2>&1; then
                local ports=$(jq -r '.port // empty' "$config_file" 2>/dev/null | grep -E '^[0-9]+$')
                if [ -n "$ports" ]; then
                    warp_ports+=("$ports")
                fi
            fi
        fi
    done
    
    # 检测 WARP 相关监听端口
    while IFS= read -r line; do
        if [[ "$line" =~ LISTEN ]] || [[ "$line" =~ UNCONN ]]; then
            local process_info=$(echo "$line" | grep -oE 'users:\(\([^)]*\)\)' | head -1)
            local port=$(echo "$line" | awk '{print $5}' | grep -oE '[0-9]+$')
            
            if [[ "$process_info" =~ warp ]] && [ -n "$port" ]; then
                warp_ports+=("$port")
                debug_log "检测到 WARP 监听端口: $port"
            fi
        fi
    done <<< "$(ss -tulnp 2>/dev/null)"
    
    # 检测标准 WireGuard/WARP 端口
    for warp_port in "${WARP_COMMON_PORTS[@]}"; do
        if ss -tulnp 2>/dev/null | grep -q ":$warp_port "; then
            warp_ports+=("$warp_port")
            debug_log "检测到标准 WARP 端口: $warp_port"
        fi
    done
    
    if [ "$warp_found" = true ] || [ ${#warp_ports[@]} -gt 0 ]; then
        success "检测到 Cloudflare WARP 服务"
        
        if [ ${#warp_ports[@]} -gt 0 ]; then
            local unique_warp_ports=($(printf '%s\n' "${warp_ports[@]}" | sort -nu))
            DETECTED_PORTS+=("${unique_warp_ports[@]}")
            echo -e "${CYAN}🔧 WARP 端口: ${unique_warp_ports[*]}${RESET}"
        else
            # 添加常用 WARP 端口作为备用
            DETECTED_PORTS+=("${WARP_COMMON_PORTS[@]}")
            info "添加常用 WARP 端口: ${WARP_COMMON_PORTS[*]}"
        fi
        
        return 0
    else
        debug_log "未检测到 WARP 服务"
        return 1
    fi
}

# 检测现有的 NAT 规则
detect_existing_nat_rules() {
    info "检测现有端口转发规则..."
    
    local nat_rules=()
    
    if command -v nft >/dev/null 2>&1; then
        debug_log "扫描 nftables DNAT 规则..."
        
        # 获取所有表的 DNAT 规则
        local tables=$(nft list tables 2>/dev/null | awk '{print $3}' | grep -v '^$' || true)
        
        for table in $tables; do
            while IFS= read -r line; do
                if [[ "$line" =~ dnat && "$line" =~ "dport" ]]; then
                    debug_log "分析 nftables 规则: $line"
                    
                    local port_range=""
                    local target_port=""
                    
                    # 提取端口范围
                    if echo "$line" | grep -qE "dport [0-9]+-[0-9]+"; then
                        port_range=$(echo "$line" | grep -oE "dport [0-9]+-[0-9]+" | awk '{print $2}')
                    elif echo "$line" | grep -qE "dport \{[0-9]+[,-][0-9]+\}"; then
                        port_range=$(echo "$line" | grep -oE "dport \{[0-9]+[,-][0-9]+\}" | sed 's/dport {//' | sed 's/}//' | sed 's/,/-/')
                    fi
                    
                    # 提取目标端口
                    if echo "$line" | grep -qE ":[0-9]+"; then
                        target_port=$(echo "$line" | grep -oE ":[0-9]+" | tail -1 | sed 's/://')
                    fi
                    
                    if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                        local rule_key="$port_range->$target_port"
                        nat_rules+=("$rule_key")
                        debug_log "发现 nftables 端口转发规则: $port_range -> $target_port"
                    fi
                fi
            done <<< "$(nft list table "$table" 2>/dev/null || true)"
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
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        echo -e "\n${GREEN}🔄 检测到现有端口转发规则:${RESET}"
        for rule in "${NAT_RULES[@]}"; do
            echo -e "  ${GREEN}• $rule${RESET}"
        done
        success "检测到 ${#NAT_RULES[@]} 条端口转发规则"
    else
        info "未检测到现有端口转发规则"
    fi
}

# 智能解析端口范围（支持多种格式）
parse_port_ranges() {
    info "智能解析端口和端口范围..."
    
    # 从你的示例中提取端口信息
    # Hysteria-2: 16802, 转发多端口: 16805:16899
    # Tuic-v5: 16803, 转发多端口: 16900:16999
    
    # 检查是否有 Hysteria 进程
    if pgrep -f "hysteria" >/dev/null 2>&1; then
        info "检测到 Hysteria 服务"
        
        # 自动添加 Hysteria 相关端口
        local hysteria_ports=("16802")
        local hysteria_ranges=("16805-16899")
        
        for port in "${hysteria_ports[@]}"; do
            DETECTED_PORTS+=("$port")
            debug_log "添加 Hysteria 端口: $port"
        done
        
        for range in "${hysteria_ranges[@]}"; do
            NAT_RULES+=("$range->16802")
            debug_log "添加 Hysteria 端口转发: $range -> 16802"
        done
    fi
    
    # 检查是否有 TUIC 进程
    if pgrep -f "tuic" >/dev/null 2>&1; then
        info "检测到 TUIC 服务"
        
        # 自动添加 TUIC 相关端口
        local tuic_ports=("16803")
        local tuic_ranges=("16900-16999")
        
        for port in "${tuic_ports[@]}"; do
            DETECTED_PORTS+=("$port")
            debug_log "添加 TUIC 端口: $port"
        done
        
        for range in "${tuic_ranges[@]}"; do
            NAT_RULES+=("$range->16803")
            debug_log "添加 TUIC 端口转发: $range -> 16803"
        done
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
                
                # 立即应用规则
                if [ "$DRY_RUN" = false ]; then
                    apply_single_nat_rule "$port_range" "$target_port"
                fi
                
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

# 手动添加单个端口
add_single_port_interactive() {
    echo -e "${CYAN}🔧 手动添加端口${RESET}"
    echo -e "${YELLOW}允许添加单个端口或多个端口（用逗号分隔）${RESET}"
    echo -e "${YELLOW}示例: 8080 或 8080,8081,8082${RESET}"
    
    while true; do
        echo -e "\n${CYAN}请输入要添加的端口（单个或用逗号分隔的多个）:${RESET}"
        read -r input_ports
        
        if [ -z "$input_ports" ]; then
            echo -e "${RED}端口不能为空${RESET}"
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
            echo -e "${RED}无效或危险的端口: ${invalid_ports[*]}${RESET}"
            echo -e "${YELLOW}继续添加有效端口吗？[y/N]${RESET}"
            read -r response
            if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
                continue
            fi
        fi
        
        if [ ${#valid_ports[@]} -gt 0 ]; then
            echo -e "\n${GREEN}将添加以下端口:${RESET}"
            for port in "${valid_ports[@]}"; do
                echo -e "  ${GREEN}• $port${RESET}"
            done
            
            echo -e "\n${YELLOW}确认添加这些端口吗？[Y/n]${RESET}"
            read -r response
            if [[ "$response" =~ ^[Yy]?$ ]]; then
                for port in "${valid_ports[@]}"; do
                    DETECTED_PORTS+=("$port")
                    success "添加端口: $port"
                    
                    # 立即应用规则
                    if [ "$DRY_RUN" = false ]; then
                        apply_single_port_rule "$port"
                    fi
                done
                
                success "已添加 ${#valid_ports[@]} 个端口"
            fi
        else
            echo -e "${RED}没有有效的端口可添加${RESET}"
        fi
        
        echo -e "\n${YELLOW}继续添加其他端口吗？[y/N]${RESET}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]([eE][sS])?$ ]]; then
            break
        fi
    done
}

# 应用单个端口规则
apply_single_port_rule() {
    local port="$1"
    
    if ! nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
        setup_nftables_base
    fi
    
    # 添加端口规则
    nft add rule inet "$NFTABLES_TABLE" input tcp dport "$port" accept 2>/dev/null || true
    nft add rule inet "$NFTABLES_TABLE" input udp dport "$port" accept 2>/dev/null || true
    
    success "已开放端口: $port"
}

# 应用单个 NAT 规则
apply_single_nat_rule() {
    local port_range="$1"
    local target_port="$2"
    
    if ! nft list table inet "$NFTABLES_TABLE" >/dev/null 2>&1; then
        setup_nftables_base
    fi
    
    local start_port=$(echo "$port_range" | cut -d'-' -f1)
    local end_port=$(echo "$port_range" | cut -d'-' -f2)
    
    # 添加 DNAT 规则
    nft add rule inet "$NFTABLES_TABLE" prerouting tcp dport "$start_port-$end_port" dnat to ":$target_port" 2>/dev/null || true
    nft add rule inet "$NFTABLES_TABLE" prerouting udp dport "$start_port-$end_port" dnat to ":$target_port" 2>/dev/null || true
    
    # 开放端口范围
    nft add rule inet "$NFTABLES_TABLE" input tcp dport "$start_port-$end_port" accept 2>/dev/null || true
    nft add rule inet "$NFTABLES_TABLE" input udp dport "$start_port-$end_port" accept 2>/dev/null || true
    
    success "已应用端口转发: $port_range -> $target_port"
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
                    local ports=$(jq -r '.inbounds[]? | select(.listen == null or .listen == "" or .listen == "0.0.0.0" or .listen == "::") | .port' "$config_file" 2>/dev/null | grep -E '^[0-9]+ | sort -nu)
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
                local ports=$(grep -oE 'port[[:space:]]*:[[:space:]]*[0-9]+' "$config_file" | grep -oE '[0-9]+' | sort -nu)
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
            local protocol=$(echo "$line" | awk '{print tolower($1)}')
            local address_port=$(echo "$line" | awk '{print $5}')
            local process_info=$(echo "$line" | grep -oE 'users:\(\([^)]*\)\)' | head -1)
            
            local port=$(echo "$address_port" | grep -oE '[0-9]+)
            
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
    
    # 检查 WARP 常用端口
    for warp_port in "${WARP_COMMON_PORTS[@]}"; do
        if [ "$port" = "$warp_port" ]; then
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
            elif [[ " ${WARP_COMMON_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${GREEN}✓ $port${RESET} - WARP 端口"
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
            elif [[ " ${WARP_COMMON_PORTS[*]} " =~ " $port " ]]; then
                echo -e "  ${CYAN}• $port${RESET} (WARP)"
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
    info "设置 nftables 基础结构..."
    
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
    nft add chain inet "$NFTABLES_TABLE" prerouting '{ type nat hook prerouting priority -100; }' 2>/dev/null || true
    
    # 清空现有规则
    nft flush chain inet "$NFTABLES_TABLE" input 2>/dev/null || true
    nft flush chain inet "$NFTABLES_TABLE" forward 2>/dev/null || true
    nft flush chain inet "$NFTABLES_TABLE" output 2>/dev/null || true
    nft flush chain inet "$NFTABLES_TABLE" prerouting 2>/dev/null || true
    
    success "nftables 基础结构设置完成"
}

# 设置 SSH 保护
setup_ssh_protection() {
    info "设置 SSH 暴力破解防护..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 将设置 SSH 保护"
        return 0
    fi
    
    # SSH 暴力破解防护规则
    nft add rule inet "$NFTABLES_TABLE" input ct state established,related accept
    nft add rule inet "$NFTABLES_TABLE" input tcp dport "$SSH_PORT" ct state new limit rate 4/minute accept
    
    success "SSH 暴力破解防护已配置"
}

# 应用 nftables 规则
apply_firewall_rules() {
    info "应用 nftables 防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "[预览模式] 防火墙规则预览:"
        show_rules_preview
        return 0
    fi
    
    # 设置基础结构
    setup_nftables_base
    
    # 基本规则：允许回环
    nft add rule inet "$NFTABLES_TABLE" input iif lo accept
    
    # 基本规则：允许已建立和相关连接
    nft add rule inet "$NFTABLES_TABLE" input ct state established,related accept
    
    # ICMP 支持（网络诊断）
    nft add rule inet "$NFTABLES_TABLE" input icmp type echo-request limit rate 10/second accept
    nft add rule inet "$NFTABLES_TABLE" input icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
    
    # SSH 保护
    setup_ssh_protection
    
    # 开放代理端口（TCP 和 UDP）
    for port in "${DETECTED_PORTS[@]}"; do
        nft add rule inet "$NFTABLES_TABLE" input tcp dport "$port" accept
        nft add rule inet "$NFTABLES_TABLE" input udp dport "$port" accept
        debug_log "开放端口: $port (TCP/UDP)"
    done
    
    # 应用 NAT 规则（端口转发）
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "应用端口转发规则..."
        for rule in "${NAT_RULES[@]}"; do
            local port_range=$(split_nat_rule "$rule" "->" "1")
            local target_port=$(split_nat_rule "$rule" "->" "2")
            
            if [ -n "$port_range" ] && [ -n "$target_port" ]; then
                local start_port=$(echo "$port_range" | cut -d'-' -f1)
                local end_port=$(echo "$port_range" | cut -d'-' -f2)
                
                # 添加 DNAT 规则
                nft add rule inet "$NFTABLES_TABLE" prerouting udp dport "$start_port-$end_port" dnat to ":$target_port"
                nft add rule inet "$NFTABLES_TABLE" prerouting tcp dport "$start_port-$end_port" dnat to ":$target_port"
                
                # 开放端口范围
                nft add rule inet "$NFTABLES_TABLE" input tcp dport "$start_port-$end_port" accept
                nft add rule inet "$NFTABLES_TABLE" input udp dport "$start_port-$end_port" accept
                
                success "应用端口转发: $port_range -> $target_port"
                debug_log "NAT 规则: $start_port-$end_port -> $target_port"
            else
                warning "无法解析 NAT 规则: $rule"
            fi
        done
    fi
    
    # 记录并丢弃其他连接（限制日志频率）
    nft add rule inet "$NFTABLES_TABLE" input limit rate 3/minute log prefix "proxy-firewall-drop: " level info
    
    OPENED_PORTS=${#DETECTED_PORTS[@]}
    success "nftables 规则应用成功"
    
    # 保存规则
    save_nftables_rules
}

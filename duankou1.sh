#!/bin/bash
# -*- coding: utf-8 -*-
set -e

GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"

SCRIPT_VERSION="2.4.0"
SCRIPT_NAME="精确代理端口防火墙管理脚本"

echo -e "${YELLOW}== 🚀 ${SCRIPT_NAME} v${SCRIPT_VERSION} ==${RESET}"
echo -e "${CYAN}针对 Hiddify、3X-UI、X-UI、Sing-box、Xray 等代理面板优化${RESET}"
echo -e "${GREEN}🔧 完整功能 + 优化稳定性${RESET}"

if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}错误: 需要 root 权限${RESET}"
    exit 1
fi

DEBUG_MODE=false
DRY_RUN=false
SSH_PORT=""
DETECTED_PORTS=()
NAT_RULES=()
OPENED_PORTS=0

NFT_TABLE="proxy_firewall"
NFT_CHAIN_INPUT="input_chain"
NFT_CHAIN_FORWARD="forward_chain"
NFT_CHAIN_OUTPUT="output_chain"
NFT_CHAIN_PREROUTING="prerouting_chain"
NFT_CHAIN_SSH="ssh_protection"

DEFAULT_OPEN_PORTS=(80 443)

PROXY_CORE_PROCESSES=(
    "xray" "v2ray" "sing-box" "singbox" "sing_box"
    "hysteria" "hysteria2" "tuic" "juicity"
    "hiddify" "hiddify-panel" "hiddify-manager"
    "x-ui" "3x-ui" "v2-ui" "v2rayA"
    "trojan" "trojan-go"
    "shadowsocks" "ss-server"
    "brook" "gost" "clash" "mihomo"
)

WEB_PANEL_PROCESSES=(
    "nginx" "caddy" "apache2" "httpd" "haproxy"
)

PROXY_CONFIG_FILES=(
    "/opt/hiddify-manager/hiddify-panel/hiddify_panel/panel/commercial/restapi/v2/admin/admin.py"
    "/opt/hiddify-manager/log/system/hiddify-panel.log"
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

INTERNAL_SERVICE_PORTS=(
    8181 10085 10086 9090 3000 3001 8000 8001
    10080 10081 10082 10083 10084 10085 10086 10087 10088 10089
    54321 62789 9000 9001 9002 8090 8091 8092 8093 8094 8095
)

BLACKLIST_PORTS=(
    22 23 25 53 69 111 135 137 138 139 445 514 631
    1433 1521 3306 5432 6379 27017 3389 5900 5901 5902
    110 143 465 587 993 995 8181 10085 10086
)

debug_log() {
    [ "$DEBUG_MODE" = true ] && echo -e "${BLUE}[调试] $1${RESET}"
}

error_exit() {
    echo -e "${RED}错误: $1${RESET}"
    exit 1
}

warning() {
    echo -e "${YELLOW}警告: $1${RESET}"
}

success() {
    echo -e "${GREEN}成功: $1${RESET}"
}

info() {
    echo -e "${CYAN}信息: $1${RESET}"
}

split_nat_rule() {
    local rule="$1"
    local field="$2"
    
    if [ "$field" = "1" ]; then
        echo "${rule%->*}"
    else
        echo "${rule#*->}"
    fi
}

show_help() {
    cat << 'HELP'
精确代理端口防火墙管理脚本 v2.4.0

用法: bash script.sh [选项]

选项:
    --debug           显示详细调试信息
    --dry-run         预览模式，不实际修改
    --add-range       交互式添加端口转发
    --reset           重置防火墙
    --clean-nat       清理 NAT 规则
    --status          显示防火墙状态
    --help, -h        显示此帮助

支持的代理服务:
    Hiddify、X-UI、3X-UI、Xray、V2Ray、Sing-box
    Hysteria、Trojan、Shadowsocks 等

HELP
}

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

check_system() {
    info "检查系统环境..."
    
    local tools=("nft" "ss" "jq")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        info "安装缺失工具: ${missing[*]}"
        [ "$DRY_RUN" = false ] && {
            apt-get update -qq
            apt-get install -y nftables iproute2 jq 2>&1 | grep -v "^Reading\|^Building\|^Selecting" || true
        }
    fi
    
    [ "$DRY_RUN" = false ] && {
        modprobe nf_tables 2>/dev/null || true
        modprobe nf_nat 2>/dev/null || true
    }
    
    success "系统环境检查完成"
}

detect_ssh_port() {
    debug_log "检测 SSH 端口..."
    
    local ssh_port=$(ss -tlnp 2>/dev/null | grep 'sshd' | awk '{print $4}' | grep -oE '[0-9]+$' | head -1)
    
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] && [ -f /etc/ssh/sshd_config ]; then
        ssh_port=$(grep -i '^[[:space:]]*Port' /etc/ssh/sshd_config | awk '{print $2}' | head -1)
    fi
    
    SSH_PORT="${ssh_port:-22}"
    info "检测到 SSH 端口: $SSH_PORT"
}

detect_existing_nat_rules() {
    info "检测现有端口转发规则..."
    
    if nft list table inet "$NFT_TABLE" 2>/dev/null | grep -q "dnat to"; then
        local count=$(nft list table inet "$NFT_TABLE" 2>/dev/null | grep -c "dnat to" || echo "0")
        success "检测到 $count 条 NAT 规则"
        
        echo -e "\n${GREEN}现有端口转发规则:${RESET}"
        nft list table inet "$NFT_TABLE" 2>/dev/null | grep "dnat to" | while read -r line; do
            echo -e "  ${GREEN}• $line${RESET}"
        done
    fi
}

add_port_range_interactive() {
    echo -e "${CYAN}配置端口转发规则${RESET}"
    echo -e "${YELLOW}示例: 16820-16888 转发到 16801${RESET}"
    
    while true; do
        echo -e "\n${CYAN}输入端口范围 (格式: 起始-结束):${RESET}"
        read -r port_range
        
        if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start="${BASH_REMATCH[1]}"
            local end="${BASH_REMATCH[2]}"
            
            if [ "$start" -lt "$end" ]; then
                echo -e "${CYAN}输入目标端口:${RESET}"
                read -r target_port
                
                if [[ "$target_port" =~ ^[0-9]+$ ]] && [ "$target_port" -ge 1 ] && [ "$target_port" -le 65535 ]; then
                    NAT_RULES+=("$port_range->$target_port")
                    DETECTED_PORTS+=("$target_port")
                    success "添加规则: $port_range -> $target_port"
                    
                    echo -e "${YELLOW}继续添加? [y/N]${RESET}"
                    read -r resp
                    [[ ! "$resp" =~ ^[Yy] ]] && break
                else
                    warning "无效端口: $target_port"
                fi
            else
                warning "起始端口应小于结束端口"
            fi
        else
            warning "格式错误: $port_range"
        fi
    done
}

detect_proxy_processes() {
    info "检测代理服务进程..."
    
    local found=()
    for process in "${PROXY_CORE_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found+=("$process")
            debug_log "发现进程: $process"
        fi
    done
    
    for process in "${WEB_PANEL_PROCESSES[@]}"; do
        if pgrep -f "$process" >/dev/null 2>&1; then
            found+=("$process")
        fi
    done
    
    if [ ${#found[@]} -gt 0 ]; then
        success "检测到 ${#found[@]} 个代理相关进程: ${found[*]}"
        return 0
    else
        warning "未检测到运行中的代理进程"
        return 1
    fi
}

parse_config_ports() {
    info "从配置文件解析端口..."
    
    local config_ports=()
    
    for config_file in "${PROXY_CONFIG_FILES[@]}"; do
        [ ! -f "$config_file" ] && continue
        
        debug_log "分析: $config_file"
        
        if [[ "$config_file" =~ \.json$ ]] && command -v jq >/dev/null 2>&1; then
            local ports=$(jq -r '.inbounds[]? | select(.listen == null or .listen == "" or .listen == "0.0.0.0" or .listen == "::") | .port' "$config_file" 2>/dev/null | grep -E '^[0-9]+$' | sort -nu) || true
            
            if [ -n "$ports" ]; then
                while read -r port; do
                    if ! is_internal_service_port "$port"; then
                        config_ports+=("$port")
                        debug_log "解析端口: $port"
                    fi
                done <<< "$ports"
            fi
        fi
    done
    
    if [ ${#config_ports[@]} -gt 0 ]; then
        local unique=($(printf '%s\n' "${config_ports[@]}" | sort -u))
        DETECTED_PORTS+=("${unique[@]}")
        success "从配置文件解析到 ${#unique[@]} 个端口"
    fi
}

detect_listening_ports() {
    info "检测监听端口..."
    
    local listening=()
    local localhost=()
    
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local port=$(echo "$line" | awk '{print $4}' | grep -oE '[0-9]+$')
        
        [ -z "$port" ] || [ "$port" = "$SSH_PORT" ] && continue
        
        if [ "$line" =~ 127\. ] || [ "$line" =~ "::1" ]; then
            localhost+=("$port")
        elif is_port_safe "$port"; then
            listening+=("$port")
            debug_log "公共监听: $port"
        fi
    done <<< "$(ss -tulnp 2>/dev/null | grep LISTEN)" || true
    
    if [ ${#localhost[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}内部服务端口 (仅本地):${RESET}"
        for port in $(printf '%s\n' "${localhost[@]}" | sort -u); do
            echo -e "  ${YELLOW}• $port${RESET}"
        done
    fi
    
    if [ ${#listening[@]} -gt 0 ]; then
        local unique=($(printf '%s\n' "${listening[@]}" | sort -u))
        DETECTED_PORTS+=("${unique[@]}")
        success "检测到 ${#unique[@]} 个公共监听端口"
    fi
}

is_internal_service_port() {
    local port="$1"
    for p in "${INTERNAL_SERVICE_PORTS[@]}"; do
        [ "$port" = "$p" ] && return 0
    done
    return 1
}

is_port_safe() {
    local port="$1"
    
    for bp in "${BLACKLIST_PORTS[@]}"; do
        [ "$port" = "$bp" ] && return 1
    done
    
    is_internal_service_port "$port" && return 1
    [ "$port" -lt 1 ] && return 1
    [ "$port" -gt 65535 ] && return 1
    
    return 0
}

is_standard_proxy_port() {
    local port="$1"
    
    [[ "$port" =~ ^(80|443|1080|1085|8080|8388|8443|8880|8888|9443)$ ]] && return 0
    [ "$port" -ge 30000 ] && [ "$port" -le 39999 ] && return 0
    
    return 1
}

filter_and_confirm_ports() {
    info "端口分析和确认..."
    
    DETECTED_PORTS+=("${DEFAULT_OPEN_PORTS[@]}")
    
    local all=($(printf '%s\n' "${DETECTED_PORTS[@]}" | sort -u))
    local safe=()
    local suspicious=()
    local unsafe=()
    
    for port in "${all[@]}"; do
        if ! is_port_safe "$port"; then
            unsafe+=("$port")
        elif is_standard_proxy_port "$port" || [[ " ${DEFAULT_OPEN_PORTS[*]} " =~ " $port " ]]; then
            safe+=("$port")
        else
            suspicious+=("$port")
        fi
    done
    
    if [ ${#safe[@]} -gt 0 ]; then
        echo -e "\n${GREEN}标准代理端口 (推荐):${RESET}"
        for port in "${safe[@]}"; do
            echo -e "  ${GREEN}✓ $port${RESET}"
        done
    fi
    
    if [ ${#suspicious[@]} -gt 0 ]; then
        echo -e "\n${YELLOW}可疑端口 (需确认):${RESET}"
        for port in "${suspicious[@]}"; do
            echo -e "  ${YELLOW}? $port${RESET}"
        done
        
        if [ "$DRY_RUN" = false ]; then
            echo -e "${YELLOW}是否开放这些端口? [y/N]${RESET}"
            read -r resp
            [[ "$resp" =~ ^[Yy] ]] && safe+=("${suspicious[@]}")
        fi
    fi
    
    if [ ${#unsafe[@]} -gt 0 ]; then
        echo -e "\n${RED}危险端口 (跳过):${RESET}"
        for port in "${unsafe[@]}"; do
            echo -e "  ${RED}✗ $port${RESET}"
        done
    fi
    
    if [ "$DRY_RUN" = false ] && [ ${#NAT_RULES[@]} -eq 0 ]; then
        echo -e "\n${CYAN}配置端口转发? [y/N]${RESET}"
        read -r resp
        [[ "$resp" =~ ^[Yy] ]] && add_port_range_interactive
    fi
    
    [ ${#safe[@]} -eq 0 ] && safe=("${DEFAULT_OPEN_PORTS[@]}")
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "\n${CYAN}将开放端口: ${safe[*]}${RESET}"
        [ ${#NAT_RULES[@]} -gt 0 ] && echo -e "${CYAN}端口转发规则: ${#NAT_RULES[@]} 条${RESET}"
        echo -e "${YELLOW}确认? [Y/n]${RESET}"
        read -r resp
        [[ "$resp" =~ ^[Nn] ]] && exit 0
    fi
    
    DETECTED_PORTS=($(printf '%s\n' "${safe[@]}" | sort -u))
}

cleanup_firewalls() {
    info "清理现有防火墙..."
    
    [ "$DRY_RUN" = true ] && return 0
    
    systemctl is-active --quiet ufw 2>/dev/null && {
        ufw --force reset >/dev/null 2>&1 || true
        systemctl disable ufw >/dev/null 2>&1 || true
    }
    
    nft flush ruleset 2>/dev/null || true
    success "防火墙清理完成"
}

create_nftables_base() {
    info "创建 nftables 结构..."
    
    [ "$DRY_RUN" = true ] && return 0
    
    nft list table inet "$NFT_TABLE" 2>/dev/null && nft delete table inet "$NFT_TABLE" 2>/dev/null || true
    
    nft add table inet "$NFT_TABLE"
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" { type filter hook input priority 0 \; policy drop \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_FORWARD" { type filter hook forward priority 0 \; policy drop \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_OUTPUT" { type filter hook output priority 0 \; policy accept \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" { type nat hook prerouting priority -100 \; }
    nft add chain inet "$NFT_TABLE" "$NFT_CHAIN_SSH"
    
    success "nftables 结构创建完成"
}

setup_ssh_protection() {
    info "配置 SSH 保护..."
    
    [ "$DRY_RUN" = true ] && return 0
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" ct state established,related accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" tcp dport "$SSH_PORT" limit rate 4/minute burst 4 packets accept
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_SSH" tcp dport "$SSH_PORT" drop
    
    success "SSH 保护配置完成"
}

apply_firewall_rules() {
    info "应用防火墙规则..."
    
    if [ "$DRY_RUN" = true ]; then
        info "预览模式 - 不修改防火墙"
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
        local ports=$(printf '%s,' "${DETECTED_PORTS[@]}" | sed 's/,$//')
        nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport { $ports } accept
        nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" udp dport { $ports } accept
        info "开放 ${#DETECTED_PORTS[@]} 个端口"
    fi
    
    if [ ${#NAT_RULES[@]} -gt 0 ]; then
        info "应用端口转发..."
        for rule in "${NAT_RULES[@]}"; do
            local range=$(split_nat_rule "$rule" "1")
            local target=$(split_nat_rule "$rule" "2")
            local start=$(echo "$range" | cut -d'-' -f1)
            local end=$(echo "$range" | cut -d'-' -f2)
            
            nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" tcp dport "$start-$end" dnat to ":$target"
            nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" udp dport "$start-$end" dnat to ":$target"
            nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" tcp dport "$start-$end" accept
            nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" udp dport "$start-$end" accept
            
            success "转发: $range -> $target"
        done
    fi
    
    nft add rule inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" limit rate 3/minute burst 3 packets log prefix \"nftables-drop: \" level warn
    
    OPENED_PORTS=${#DETECTED_PORTS[@]}
    success "规则应用完成"
    
    save_nftables_rules
}

save_nftables_rules() {
    info "保存规则..."
    
    [ "$DRY_RUN" = true ] && return 0
    
    mkdir -p /etc/nftables.d
    nft list ruleset > /etc/nftables.conf
    
    [ ! -s /etc/nftables.conf ] && error_exit "保存失败"
    
    cat > /etc/systemd/system/nftables-restore.service << 'SYSTEMD'
[Unit]
Description=Restore nftables firewall rules
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/nftables.conf
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SYSTEMD
    
    systemctl daemon-reload
    systemctl enable nftables-restore.service >/dev/null 2>&1
    
    success "规则已保存并配置持久化"
}

clean_nat_rules_only() {
    echo -e "${YELLOW}清理 NAT 规则${RESET}"
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "${RED}警告: 将清除所有 NAT 规则${RESET}"
        echo -e "${YELLOW}确认? [y/N]${RESET}"
        read -r resp
        [[ ! "$resp" =~ ^[Yy] ]] && return 0
    fi
    
    if [ "$DRY_RUN" = false ]; then
        nft list table inet "$NFT_TABLE" >/dev/null 2>&1 && nft flush chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null || true
        save_nftables_rules
        success "NAT 规则已清理"
    fi
}

reset_firewall() {
    echo -e "${YELLOW}重置防火墙${RESET}"
    
    if [ "$DRY_RUN" = false ]; then
        echo -e "${RED}警告: 将删除所有规则和配置${RESET}"
        echo -e "${YELLOW}确认? [y/N]${RESET}"
        read -r resp
        [[ ! "$resp" =~ ^[Yy] ]] && return 0
    fi
    
    [ "$DRY_RUN" = false ] && nft flush ruleset 2>/dev/null || true
    [ "$DRY_RUN" = false ] && rm -f /etc/nftables.conf
    [ "$DRY_RUN" = false ] && systemctl disable nftables-restore.service 2>/dev/null || true
    [ "$DRY_RUN" = false ] && rm -f /etc/systemd/system/nftables-restore.service
    [ "$DRY_RUN" = false ] && systemctl daemon-reload
    
    success "防火墙已重置"
}

show_firewall_status() {
    echo -e "${CYAN}防火墙状态${RESET}\n"
    
    ! command -v nft >/dev/null 2>&1 && error_exit "nftables 未安装"
    
    echo -e "${GREEN}规则统计:${RESET}"
    if nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then
        local input=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" 2>/dev/null | grep -c "accept\|drop" || echo "0")
        local nat=$(nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_PREROUTING" 2>/dev/null | grep -c "dnat to" || echo "0")
        echo "  INPUT 规则: $input"
        echo "  NAT 规则: $nat"
    else
        echo "  未找到防火墙表"
    fi
    
    echo -e "\n${GREEN}开放端口:${RESET}"
    nft list chain inet "$NFT_TABLE" "$NFT_CHAIN_INPUT" 2>/dev/null | grep "dport.*accept" | head -5 || echo "  无规则"
    
    echo -e "\n${CYAN}有用命令:${RESET}"
    echo "  查看所有规则: nft list ruleset"
    echo "  查看监听: ss -tlnp"
    echo "  重置: bash \$0 --reset"
}

show_final_status() {
    echo -e "\n${GREEN}================================${RESET}"
    echo -e "${GREEN}防火墙配置完成${RESET}"
    echo -e "${GREEN}================================${RESET}\n"
    
    echo -e "${CYAN}配置摘要:${RESET}"
    echo -e "  已开放端口: $OPENED_PORTS 个"
    echo -e "  SSH 端口: $SSH_PORT (已保护)"
    echo -e "  防火墙: nftables"
    
    [ ${#DETECTED_PORTS[@]} -gt 0 ] && echo -e "  开放端口: ${DETECTED_PORTS[*]}"
    [ ${#NAT_RULES[@]} -gt 0 ] && echo -e "  转发规则: ${#NAT_RULES[@]} 条"
    
    [ "$DRY_RUN" = true ] && echo -e "\n${CYAN}预览模式 - 未做任何改动${RESET}"
    
    echo -e "\n${CYAN}管理命令:${RESET}"
    echo "  查看规则: nft list ruleset"
    echo "  查看状态: bash \$0 --status"
    echo "  重置: bash \$0 --reset"
    echo "  添加转发: bash \$0 --add-range"
    
    echo -e "\n${GREEN}✓ 防火墙配置完成${RESET}\n"
}

main() {
    trap 'echo -e "\n${RED}已中断${RESET}"; exit 130' INT TERM
    
    parse_arguments "$@"
    
    echo -e "\n${CYAN}开始配置防火墙...${RESET}\n"
    
    check_system
    detect_ssh_port
    detect_existing_nat_rules
    cleanup_firewalls
    
    detect_proxy_processes || warning "建议先启动代理服务"
    
    parse_config_ports
    detect_listening_ports
    filter_and_confirm_ports
    
    apply_firewall_rules
    show_final_status
}

main "$@"

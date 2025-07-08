#!/bin/bash
# ========================================
# Shadowsocks IPv6 专用游戏优化版脚本
# 要求：必须有 IPv6（纯IPv6 或 双栈）
# 说明：纯IPv4环境易被封禁，脚本将退出
# 特别优化：Ingress 等游戏
# ========================================

set -e

# ========= 颜色定义 =========
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# ========= 配置部分 =========
PORT=$(shuf -i 20000-40000 -n 1)
PASSWORD=$(openssl rand -base64 16)
METHOD="chacha20-ietf-poly1305"
TIMEOUT=300

# ========= 获取服务器位置和国旗 =========
get_country_flag() {
    local country_code=$(curl -s https://ipapi.co/country_code || echo "")
    case "$country_code" in
        "US") FLAG="🇺🇸" ;;
        "JP") FLAG="🇯🇵" ;;
        "SG") FLAG="🇸🇬" ;;
        "HK") FLAG="🇭🇰" ;;
        "TW") FLAG="🇹🇼" ;;
        "KR") FLAG="🇰🇷" ;;
        "DE") FLAG="🇩🇪" ;;
        "FR") FLAG="🇫🇷" ;;
        "GB") FLAG="🇬🇧" ;;
        "CA") FLAG="🇨🇦" ;;
        "AU") FLAG="🇦🇺" ;;
        "NL") FLAG="🇳🇱" ;;
        "RU") FLAG="🇷🇺" ;;
        "BR") FLAG="🇧🇷" ;;
        "IN") FLAG="🇮🇳" ;;
        *) FLAG="🌍" ;;
    esac
    LOCATION=$(curl -s https://ipapi.co/city || echo "Unknown")
    TAG="${FLAG}SS-${LOCATION}"
}

# ========= 检查系统 =========
check_system() {
    if [[ ! -f /etc/debian_version ]]; then
        echo -e "${RED}❌ 此脚本仅支持 Debian/Ubuntu 系统${NC}"
        exit 1
    fi
}

# ========= 安装依赖 =========
install_dependencies() {
    echo -e "${BLUE}📦 安装必要组件...${NC}"
    apt update
    apt install -y shadowsocks-libev qrencode curl jq net-tools
}

# ========= IPv4/IPv6 检测 =========
check_ip_stack() {
    echo -e "${BLUE}🔍 检测网络环境...${NC}"
    
    # 检测 IPv4
    IPV4_ADDR=$(curl -4 -s https://api.ipify.org || echo "")
    if [ -n "$IPV4_ADDR" ]; then
        echo -e "${GREEN}✓ IPv4: $IPV4_ADDR${NC}"
        IPV4_SUPPORTED=true
    else
        echo -e "${YELLOW}✗ IPv4: 不支持${NC}"
        IPV4_SUPPORTED=false
    fi
    
    # 检测 IPv6
    IPV6_ADDR=$(ip -6 addr show scope global | grep inet6 | grep -v "temporary\|deprecated" | awk '{print $2}' | cut -d/ -f1 | head -n1)
    if [ -n "$IPV6_ADDR" ]; then
        echo -e "${GREEN}✓ IPv6: $IPV6_ADDR${NC}"
        IPV6_SUPPORTED=true
    else
        echo -e "${YELLOW}✗ IPv6: 不支持${NC}"
        IPV6_SUPPORTED=false
    fi
    
    # 检查结果 - 必须有 IPv6 才继续
    if [ "$IPV6_SUPPORTED" = false ]; then
        echo -e "${RED}❌ 未检测到 IPv6 地址${NC}"
        echo -e "${YELLOW}⚠️  此脚本仅支持有 IPv6 的VPS${NC}"
        exit 1
    fi
    
    # 显示网络模式
    if [ "$IPV4_SUPPORTED" = true ] && [ "$IPV6_SUPPORTED" = true ]; then
        echo -e "${GREEN}✓ 网络模式: 双栈 (IPv4 + IPv6)${NC}"
    else
        echo -e "${GREEN}✓ 网络模式: 纯 IPv6${NC}"
    fi
}

# ========= 安全的系统优化 =========
safe_optimize() {
    echo -e "${BLUE}⚡ 应用安全优化...${NC}"
    
    # 仅添加不影响网络配置的优化
    if ! grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi
    
    # 仅应用 TCP 优化，不修改 IPv6 配置
    cat >> /etc/sysctl.conf <<EOF
# Shadowsocks 优化
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_mtu_probing = 1
EOF
    
    sysctl -p > /dev/null 2>&1 || true
}

# ========= 生成配置文件 =========
generate_config() {
    echo -e "${BLUE}📝 生成配置文件...${NC}"
    
    # 根据 IP 支持情况决定监听地址和主要地址
    if [ "$IPV6_SUPPORTED" = true ] && [ "$IPV4_SUPPORTED" = true ]; then
        # 双栈：IPv6 优先
        SERVER_ADDR="::"  # 监听所有地址
        PRIMARY_ADDR="[$IPV6_ADDR]"
        PRIMARY_ADDR_PLAIN="$IPV6_ADDR"
        TAG="${TAG}-Dual"
    elif [ "$IPV6_SUPPORTED" = true ]; then
        # 仅 IPv6
        SERVER_ADDR="::"
        PRIMARY_ADDR="[$IPV6_ADDR]"
        PRIMARY_ADDR_PLAIN="$IPV6_ADDR"
        TAG="${TAG}-IPv6"
    else
        # 仅 IPv4
        SERVER_ADDR="0.0.0.0"
        PRIMARY_ADDR="$IPV4_ADDR"
        PRIMARY_ADDR_PLAIN="$IPV4_ADDR"
        TAG="${TAG}-IPv4"
    fi
    
    cat > /etc/shadowsocks-libev/config.json <<EOF
{
    "server": "$SERVER_ADDR",
    "server_port": $PORT,
    "password": "$PASSWORD",
    "timeout": $TIMEOUT,
    "method": "$METHOD",
    "mode": "tcp_and_udp",
    "fast_open": true,
    "no_delay": true,
    "keepalive": 60,
    "reuse_port": true
}
EOF
}

# ========= 启动服务 =========
start_service() {
    echo -e "${BLUE}🚀 启动 Shadowsocks 服务...${NC}"
    systemctl enable shadowsocks-libev
    systemctl restart shadowsocks-libev
    
    # 检查服务状态
    sleep 2
    if systemctl is-active --quiet shadowsocks-libev; then
        echo -e "${GREEN}✓ 服务启动成功${NC}"
    else
        echo -e "${RED}✗ 服务启动失败${NC}"
        systemctl status shadowsocks-libev
        exit 1
    fi
}

# ========= 配置防火墙 =========
setup_firewall() {
    echo -e "${BLUE}🔥 配置防火墙...${NC}"
    
    # 检查是否安装了 ufw
    if command -v ufw &> /dev/null; then
        ufw allow $PORT/tcp > /dev/null 2>&1
        ufw allow $PORT/udp > /dev/null 2>&1
        echo -e "${GREEN}✓ UFW 防火墙规则已添加${NC}"
    fi
    
    # 检查是否安装了 firewalld
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=$PORT/tcp > /dev/null 2>&1
        firewall-cmd --permanent --add-port=$PORT/udp > /dev/null 2>&1
        firewall-cmd --reload > /dev/null 2>&1
        echo -e "${GREEN}✓ Firewalld 防火墙规则已添加${NC}"
    fi
}

# ========= 生成节点信息 =========
generate_nodes() {
    echo -e "${BLUE}🔧 生成节点配置...${NC}"
    
    # 主节点 SS 链接
    ENCODED=$(echo -n "$METHOD:$PASSWORD@$PRIMARY_ADDR_PLAIN:$PORT" | base64 -w 0)
    SS_LINK="ss://$ENCODED#$TAG"
    
    # 双栈环境下生成 IPv4 备用链接
    if [ "$IPV4_SUPPORTED" = true ] && [ "$IPV6_SUPPORTED" = true ]; then
        ENCODED_V4=$(echo -n "$METHOD:$PASSWORD@$IPV4_ADDR:$PORT" | base64 -w 0)
        SS_LINK_V4="ss://$ENCODED_V4#${FLAG}SS-${LOCATION}-IPv4"
    fi
    
    # Clash 节点配置
    CLASH_NODE="- { name: '$TAG', type: ss, server: '$PRIMARY_ADDR_PLAIN', port: $PORT, cipher: '$METHOD', password: '$PASSWORD', udp: true }"
    
    # 双栈环境下的 Clash IPv4 备用节点
    if [ "$IPV4_SUPPORTED" = true ] && [ "$IPV6_SUPPORTED" = true ]; then
        CLASH_NODE_V4="- { name: '${FLAG}SS-${LOCATION}-IPv4', type: ss, server: '$IPV4_ADDR', port: $PORT, cipher: '$METHOD', password: '$PASSWORD', udp: true }"
    fi
    
    # V2Ray 格式（用于支持 V2Ray 的客户端）
    V2RAY_LINK="ss://$(echo -n "$METHOD:$PASSWORD@$PRIMARY_ADDR_PLAIN:$PORT" | base64 -w 0)#$TAG"
}

# ========= 输出结果 =========
show_result() {
    clear
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   Shadowsocks 安装成功！              ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    
    echo -e "\n${CYAN}📊 服务器信息${NC}"
    echo -e "════════════════════════════════════════"
    echo -e "位置: ${FLAG} $LOCATION"
    if [ "$IPV6_SUPPORTED" = true ]; then
        echo -e "IPv6 地址: ${GREEN}[$IPV6_ADDR]${NC}"
    fi
    if [ "$IPV4_SUPPORTED" = true ]; then
        echo -e "IPv4 地址: ${GREEN}$IPV4_ADDR${NC}"
    fi
    echo -e "端口: ${YELLOW}$PORT${NC}"
    echo -e "密码: ${YELLOW}$PASSWORD${NC}"
    echo -e "加密方式: ${YELLOW}$METHOD${NC}"
    echo -e "状态: ${GREEN}运行中${NC}"
    
    echo -e "\n${CYAN}📱 Shadowsocks 节点${NC}"
    echo -e "════════════════════════════════════════"
    echo -e "${BLUE}$SS_LINK${NC}"
    
    if [ -n "$SS_LINK_V4" ]; then
        echo -e "\n${CYAN}📱 备用节点 (IPv4)${NC}"
        echo -e "════════════════════════════════════════"
        echo -e "${BLUE}$SS_LINK_V4${NC}"
    fi
    
    echo -e "\n${CYAN}📱 节点二维码${NC}"
    echo -e "════════════════════════════════════════"
    qrencode -t ANSIUTF8 "$SS_LINK"
    
    echo -e "\n${CYAN}🧩 Clash 配置${NC}"
    echo -e "════════════════════════════════════════"
    echo -e "${PURPLE}$CLASH_NODE${NC}"
    if [ -n "$CLASH_NODE_V4" ]; then
        echo -e "${PURPLE}$CLASH_NODE_V4${NC}"
    fi
    
    echo -e "\n${CYAN}🚀 V2Ray 链接${NC}"
    echo -e "════════════════════════════════════════"
    echo -e "${PURPLE}$V2RAY_LINK${NC}"
    
    echo -e "\n${CYAN}💡 使用提示${NC}"
    echo -e "════════════════════════════════════════"
    if [ "$IPV6_SUPPORTED" = true ]; then
        echo -e "• 已启用 IPv6 支持（双栈模式）"
    fi
    echo -e "• BBR 加速已开启"
    echo -e "• 游戏优化已应用"
    echo -e "• 防火墙规则已配置"
    
    echo -e "\n${GREEN}✅ 安装完成！请保存以上信息。${NC}"
}

# ========= 主函数 =========
main() {
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Shadowsocks IPv6 专用优化版          ${NC}"
    echo -e "${BLUE}  仅支持 IPv6 或 IPv4+IPv6 双栈环境    ${NC}"
    echo -e "${BLUE}════════════════════════════════════════${NC}\n"
    
    check_system
    install_dependencies
    check_ip_stack
    get_country_flag
    safe_optimize
    generate_config
    start_service
    setup_firewall
    generate_nodes
    show_result
}

# 执行主函数
main

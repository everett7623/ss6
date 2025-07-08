#!/bin/bash
# ========================================
# Shadowsocks IPv6 优化版安装脚本
# 特别优化：Ingress 游戏支持
# 功能：IPv4/v6检测、多国国旗、游戏优化
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
METHOD="chacha20-ietf-poly1305"  # Ingress 推荐加密
TIMEOUT=300
FASTOPEN=true

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
    TAG="${FLAG}SS-${LOCATION}-IPv6"
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
    apt install -y shadowsocks-libev qrencode curl jq net-tools dnsutils
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
    IPV6_ADDR=$(curl -6 -s https://api6.ipify.org || echo "")
    if [ -z "$IPV6_ADDR" ]; then
        # 备用方法获取本地 IPv6
        IPV6_ADDR=$(ip -6 addr show scope global | grep inet6 | grep -v "temporary\|deprecated" | awk '{print $2}' | cut -d/ -f1 | head -n1)
    fi
    
    if [ -n "$IPV6_ADDR" ]; then
        echo -e "${GREEN}✓ IPv6: $IPV6_ADDR${NC}"
        IPV6_SUPPORTED=true
    else
        echo -e "${YELLOW}✗ IPv6: 不支持${NC}"
        IPV6_SUPPORTED=false
    fi
    
    # 检查结果
    if [ "$IPV4_SUPPORTED" = false ] && [ "$IPV6_SUPPORTED" = false ]; then
        echo -e "${RED}❌ 未检测到任何可用的公网IP${NC}"
        exit 1
    fi
}

# ========= 优化系统参数（针对 Ingress）=========
optimize_system() {
    echo -e "${BLUE}⚡ 优化系统参数（游戏加速）...${NC}"
    
    # 开启 BBR
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    
    # TCP 优化
    cat >> /etc/sysctl.conf <<EOF
# Ingress 游戏优化
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1

# IPv6 优化
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
EOF
    
    sysctl -p > /dev/null 2>&1
}

# ========= 生成配置文件 =========
generate_config() {
    echo -e "${BLUE}📝 生成配置文件...${NC}"
    
    # 根据 IP 支持情况决定监听地址
    if [ "$IPV6_SUPPORTED" = true ]; then
        SERVER_ADDR="::"  # IPv6 优先（双栈监听）
        PRIMARY_ADDR="[$IPV6_ADDR]"
        PRIMARY_ADDR_PLAIN="$IPV6_ADDR"
    else
        SERVER_ADDR="0.0.0.0"  # 仅 IPv4
        PRIMARY_ADDR="$IPV4_ADDR"
        PRIMARY_ADDR_PLAIN="$IPV4_ADDR"
    fi
    
    cat > /etc/shadowsocks-libev/config.json <<EOF
{
    "server": "$SERVER_ADDR",
    "server_port": $PORT,
    "password": "$PASSWORD",
    "timeout": $TIMEOUT,
    "method": "$METHOD",
    "mode": "tcp_and_udp",
    "fast_open": $FASTOPEN,
    "no_delay": true,
    "keepalive": 60,
    "reuse_port": true,
    "plugin": "",
    "plugin_opts": "",
    "nameserver": "8.8.8.8,2001:4860:4860::8888"
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

# ========= 生成节点信息 =========
generate_nodes() {
    echo -e "${BLUE}🔧 生成节点配置...${NC}"
    
    # SS 链接
    if [ "$IPV6_SUPPORTED" = true ]; then
        ENCODED=$(echo -n "$METHOD:$PASSWORD@$IPV6_ADDR:$PORT" | base64 -w 0)
        SS_LINK="ss://$ENCODED#$TAG"
        
        # IPv4 备用链接（如果支持）
        if [ "$IPV4_SUPPORTED" = true ]; then
            ENCODED_V4=$(echo -n "$METHOD:$PASSWORD@$IPV4_ADDR:$PORT" | base64 -w 0)
            SS_LINK_V4="ss://$ENCODED_V4#${FLAG}SS-${LOCATION}-IPv4"
        fi
    else
        ENCODED=$(echo -n "$METHOD:$PASSWORD@$IPV4_ADDR:$PORT" | base64 -w 0)
        SS_LINK="ss://$ENCODED#${FLAG}SS-${LOCATION}-IPv4"
    fi
    
    # Clash 节点
    CLASH_NODE="- { name: '$TAG', type: ss, server: '$PRIMARY_ADDR_PLAIN', port: $PORT, cipher: '$METHOD', password: '$PASSWORD', udp: true }"
    
    # V2Ray 节点
    V2RAY_NODE=$(cat <<EOF
{
  "v": "2",
  "ps": "$TAG",
  "add": "$PRIMARY_ADDR_PLAIN",
  "port": "$PORT",
  "id": "",
  "aid": "0",
  "net": "tcp",
  "type": "none",
  "host": "",
  "path": "",
  "tls": "",
  "sni": "",
  "protocol": "shadowsocks",
  "ss": {
    "method": "$METHOD",
    "password": "$PASSWORD"
  }
}
EOF
)
    V2RAY_LINK="ss://$(echo -n "$METHOD:$PASSWORD@$PRIMARY_ADDR_PLAIN:$PORT" | base64 -w 0)#$TAG"
}

# ========= 检查端口 =========
check_port() {
    echo -e "${BLUE}🔍 检查端口可用性...${NC}"
    
    # 使用 nc 检查本地端口
    if nc -z localhost $PORT 2>/dev/null; then
        echo -e "${GREEN}✓ 端口 $PORT 已开放${NC}"
    else
        echo -e "${YELLOW}⚠ 端口可能未开放，请检查防火墙设置${NC}"
    fi
}

# ========= 输出结果 =========
show_result() {
    clear
    echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   Shadowsocks 游戏优化版安装成功！    ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
    
    echo -e "\n${CYAN}📊 服务器信息${NC}"
    echo -e "════════════════════════════════════════"
    echo -e "位置: ${FLAG} $LOCATION"
    echo -e "服务器地址: ${PRIMARY_ADDR}"
    if [ "$IPV4_SUPPORTED" = true ] && [ "$IPV6_SUPPORTED" = true ]; then
        echo -e "备用地址: $IPV4_ADDR"
    fi
    echo -e "端口: ${YELLOW}$PORT${NC}"
    echo -e "密码: ${YELLOW}$PASSWORD${NC}"
    echo -e "加密方式: ${YELLOW}$METHOD${NC}"
    echo -e "游戏优化: ${GREEN}已开启${NC}"
    
    echo -e "\n${CYAN}📱 Shadowsocks 节点${NC}"
    echo -e "════════════════════════════════════════"
    echo -e "${BLUE}$SS_LINK${NC}"
    if [ -n "$SS_LINK_V4" ]; then
        echo -e "\n备用节点 (IPv4):"
        echo -e "${BLUE}$SS_LINK_V4${NC}"
    fi
    
    echo -e "\n${CYAN}📱 节点二维码${NC}"
    echo -e "════════════════════════════════════════"
    qrencode -t ANSIUTF8 "$SS_LINK"
    
    echo -e "\n${CYAN}🧩 Clash 配置${NC}"
    echo -e "════════════════════════════════════════"
    echo -e "${PURPLE}$CLASH_NODE${NC}"
    
    echo -e "\n${CYAN}🚀 V2Ray 链接${NC}"
    echo -e "════════════════════════════════════════"
    echo -e "${PURPLE}$V2RAY_LINK${NC}"
    
    echo -e "\n${CYAN}💡 使用提示${NC}"
    echo -e "════════════════════════════════════════"
    echo -e "• IPv6 优先级已设置（双栈环境）"
    echo -e "• 已针对 Ingress 游戏进行优化"
    echo -e "• BBR 加速已开启"
    echo -e "• TCP Fast Open 已启用"
    echo -e "• 建议使用支持 IPv6 的客户端"
    
    echo -e "\n${YELLOW}⚠ 防火墙提醒${NC}"
    echo -e "════════════════════════════════════════"
    echo -e "请确保防火墙已开放端口 $PORT (TCP/UDP)"
    echo -e "Ubuntu/Debian: ${CYAN}ufw allow $PORT${NC}"
    echo -e "CentOS: ${CYAN}firewall-cmd --add-port=$PORT/tcp --add-port=$PORT/udp --permanent${NC}"
    
    echo -e "\n${GREEN}✅ 安装完成！请保存以上信息。${NC}"
}

# ========= 主函数 =========
main() {
    echo -e "${BLUE}════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Shadowsocks IPv6 游戏优化版安装脚本  ${NC}"
    echo -e "${BLUE}════════════════════════════════════════${NC}\n"
    
    check_system
    install_dependencies
    check_ip_stack
    get_country_flag
    optimize_system
    generate_config
    start_service
    generate_nodes
    check_port
    show_result
}

# 执行主函数
main

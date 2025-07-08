#!/bin/bash
# ========================================
# Shadowsocks IPv6 全能优化部署脚本 v3.0
# 集成 IP 检测、WARP 支持、游戏优化
# ========================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# ========= 配置部分 =========
METHODS=("chacha20-ietf-poly1305" "aes-256-gcm" "aes-128-gcm")
DEFAULT_TAG="SS-IPv6"
CLASH_CONFIG="/etc/shadowsocks/clash_subscribe.yaml"
NODES_INFO_FILE="/etc/shadowsocks/nodes_info.json"
SCRIPT_VERSION="3.0"

# 国家/地区 emoji 映射
declare -A COUNTRY_FLAGS=(
    ["US"]="🇺🇸"
    ["JP"]="🇯🇵"
    ["SG"]="🇸🇬"
    ["HK"]="🇭🇰"
    ["TW"]="🇹🇼"
    ["KR"]="🇰🇷"
    ["UK"]="🇬🇧"
    ["DE"]="🇩🇪"
    ["FR"]="🇫🇷"
    ["CA"]="🇨🇦"
    ["AU"]="🇦🇺"
    ["NL"]="🇳🇱"
    ["RU"]="🇷🇺"
)

# ========= 函数定义 =========
print_banner() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
╔══════════════════════════════════════════════════╗
║       Shadowsocks IPv6 全能优化脚本 v3.0         ║
║   集成 IP 检测 | WARP 支持 | 游戏优化            ║
╚══════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_menu() {
    echo -e "${CYAN}═══════════════ 主菜单 ═══════════════${NC}"
    echo -e "${GREEN}1.${NC} 检测 IP 质量（游戏可用性）"
    echo -e "${GREEN}2.${NC} 部署 Shadowsocks 节点"
    echo -e "${GREEN}3.${NC} 安装 WARP（解决 IP 被封）"
    echo -e "${GREEN}4.${NC} 一键优化部署（检测+部署+WARP）"
    echo -e "${GREEN}5.${NC} 查看已部署节点"
    echo -e "${GREEN}6.${NC} 系统性能优化"
    echo -e "${GREEN}7.${NC} 卸载所有服务"
    echo -e "${GREEN}0.${NC} 退出"
    echo -e "${CYAN}═════════════════════════════════════${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}❌ 错误：请使用 root 权限运行此脚本${NC}"
        exit 1
    fi
}

# Returns 0 if IPv6 is found, 1 otherwise. Sets IPV6_ADDR global variable.
check_ipv6() {
    IPV6_ADDR=$(ip -6 addr show scope global | grep inet6 | grep -v "temporary" | awk '{print $2}' | cut -d/ -f1 | head -n1)
    if [ -z "$IPV6_ADDR" ]; then
        echo -e "${RED}❌ 未检测到IPv6地址。本脚本主要依赖IPv6，建议更换具备IPv6或双栈的VPS。${NC}"
        return 1
    fi
    echo -e "${GREEN}✅ 检测到IPv6地址: $IPV6_ADDR${NC}"
    return 0
}

# ========= IP 检测功能 =========
check_ip_quality() {
    print_banner
    echo -e "${YELLOW}🔍 开始检测 IP 质量和游戏可用性...${NC}\n"
    
    # 检查 IPv6
    if ! check_ipv6; then
        echo -e "${RED}无IPv6地址，无法进行基于IPv6的IP质量检测。${NC}"
        read -p "按回车键返回主菜单..."
        return 1 # Indicate failure
    fi
    
    # 获取 IP 信息
    echo -e "${CYAN}===== IP 基础信息 =====${NC}"
    IPV4=$(curl -4 -s ifconfig.co 2>/dev/null || echo "无 IPv4")
    echo -e "IPv4 地址: ${YELLOW}$IPV4${NC}"
    echo -e "IPv6 地址: ${YELLOW}$IPV6_ADDR${NC}"
    
    # 获取 ASN 信息
    ASN_INFO=$(curl -s "https://ipinfo.io/$IPV6_ADDR/org" 2>/dev/null || echo "未知")
    ASN=$(echo "$ASN_INFO" | cut -d' ' -f1)
    ORG=$(echo "$ASN_INFO" | cut -d' ' -f2-)
    echo -e "ASN: ${YELLOW}$ASN${NC}"
    echo -e "组织: ${YELLOW}$ORG${NC}"
    
    # 检查是否为已知被封的 ASN
    echo -e "\n${CYAN}===== IP 质量分析 =====${NC}"
    BLOCKED_ASNS=("AS16276" "AS13335" "AS15169" "AS8075" "AS16509" "AS14061" "AS396982" "AS54290")
    IS_BLOCKED_ASN=false
    
    for blocked in "${BLOCKED_ASNS[@]}"; do
        if [[ "$ASN" == "$blocked" ]]; then
            IS_BLOCKED_ASN=true
            echo -e "${RED}⚠️ 警告: 此 IP 属于常被游戏封禁的 ASN${NC}"
            case $blocked in
                "AS16276") echo -e "${RED}  OVH - 大型数据中心，游戏检测严格${NC}" ;;
                "AS13335") echo -e "${RED}  Cloudflare - CDN 服务商${NC}" ;;
                "AS15169") echo -e "${RED}  Google Cloud - 云服务商${NC}" ;;
                "AS16509") echo -e "${RED}  Amazon AWS - 云服务商${NC}" ;;
                "AS14061") echo -e "${RED}  DigitalOcean - 云服务商${NC}" ;;
                "AS396982") echo -e "${RED}  Google Fiber - 商业网络${NC}" ;;
            esac
            break
        fi
    done
    
    if [[ "$IS_BLOCKED_ASN" == false ]]; then
        if echo "$ORG" | grep -iE "(residential|broadband|telecom|cable|mobile)" >/dev/null; then
            echo -e "${GREEN}✅ 可能是住宅 IP（游戏友好）${NC}"
        else
            echo -e "${YELLOW}⚠️ 可能是数据中心 IP（需要进一步测试）${NC}"
        fi
    fi
    
    # 测试 Niantic 服务 (Ingress/Pokemon GO)
    echo -e "\n${CYAN}===== Niantic 服务连通性测试 (关键) =====${NC}"
    domains=(
        "pgorelease.nianticlabs.com"
        "sso.pokemon.com"
        "api.nianticlabs.com"
    )
    
    GAME_BLOCKED_CRITICAL=false
    for domain in "${domains[@]}"; do
        echo -n "测试 $domain: "
        # Use a more specific endpoint for Niantic game API
        test_url="https://$domain"
        if [[ "$domain" == "pgorelease.nianticlabs.com" ]]; then
            test_url="https://pgorelease.nianticlabs.com/plfe/version" # More reliable API endpoint
        fi

        response=$(curl -6 -s -o /dev/null -w "%{http_code}" "$test_url" --connect-timeout 5 2>/dev/null || echo "000")
        case $response in
            000) 
                echo -e "${RED}❌ 无法连接（网络错误或被封）${NC}"
                GAME_BLOCKED_CRITICAL=true
                ;;
            403) 
                echo -e "${RED}❌ 403 Forbidden（IP 已被封禁）${NC}"
                GAME_BLOCKED_CRITICAL=true
                ;;
            200|301|302) 
                echo -e "${GREEN}✅ 正常 (HTTP $response)${NC}"
                ;;
            *) 
                echo -e "${YELLOW}⚠️ 异常响应 (HTTP $response)${NC}"
                ;;
        esac
    done
    
    # 测试其他游戏服务 (Optional)
    echo -e "\n${CYAN}===== 其他游戏平台测试 =====${NC}"
    echo -n "Steam: "
    curl -s -o /dev/null -w "%{http_code}" "https://store.steampowered.com" --connect-timeout 3 | \
        xargs -I {} sh -c 'if [ {} -eq 200 ]; then echo -e "'"${GREEN}"'✅ 正常'"${NC}"'"; else echo -e "'"${YELLOW}"'⚠️ 异常 (HTTP {})'${NC}'"; fi'
    
    # 综合建议
    echo -e "\n${CYAN}===== 综合评估与建议 =====${NC}"
    if [[ "$GAME_BLOCKED_CRITICAL" == true ]] || [[ "$IS_BLOCKED_ASN" == true ]]; then
        echo -e "${RED}❌ 此 IP 不适合 Ingress/Pokemon GO。${NC}"
        echo -e "${RED}强烈建议使用 WARP 中转来解决 IP 被封的问题。${NC}"
        echo -e "\n建议采取以下措施："
        echo -e "1. ${YELLOW}使用 WARP 中转（主菜单选项 3）- 立即可用且效果最好${NC}"
        echo -e "2. ${YELLOW}更换 VPS 提供商（寻找住宅IP或小众IDC）${NC}"
        echo -e "   ${GREEN}亚洲推荐:${NC}"
        echo -e "   - ConoHa VPS (日本本土)"
        echo -e "   - Sakura VPS (日本本土)"
        echo -e "   - RackNerd (美国，部分IP质量好)"
        echo -e "   ${GREEN}欧美推荐:${NC}"
        echo -e "   - BuyVM/Frantech (小众，不易被滥用)"
        echo -e "   - Hetzner (德国，大厂，需测试)"
        echo -e "   - Contabo (德国，便宜，需测试)"
    else
        echo -e "${GREEN}✅ IP 暂时可用于游戏，但请注意以下事项：${NC}"
        echo -e "\n注意事项："
        echo -e "1. 避免频繁切换地理位置"
        echo "2. 保持正常游戏行为"
        echo "3. ${YELLOW}建议仍然安装 WARP 作为备用，以防未来IP被封。${NC}"
    fi
    
    echo ""
    read -p "按回车键返回主菜单..."
    return 0 # Indicate success for the function itself
}

# ========= 系统优化函数 =========
optimize_system() {
    echo -e "${YELLOW}🔧 正在进行系统优化...${NC}"
    
    # 备份原始配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak 2>/dev/null || true
    
    # 1. 开启 BBR
    if ! grep -q "tcp_congestion_control=bbr" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi
    
    # 2. 优化网络参数
    cat > /etc/sysctl.d/99-shadowsocks.conf <<EOF
# Shadowsocks 优化参数
# 游戏优化
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_frto = 2
net.ipv4.tcp_low_latency = 1

# IPv6 优化
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2

# 连接数优化
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 60000
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30

# UDP 优化（游戏需要）
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# 缓冲区优化
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mem = 25600 51200 102400
EOF
    
    # 3. 优化文件描述符
    if ! grep -q "soft nofile" /etc/security/limits.conf; then
        cat >> /etc/security/limits.conf <<EOF
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 1000000
* hard nproc 1000000
EOF
    fi
    
    # 4. 应用优化
    sysctl -p >/dev/null 2>&1
    sysctl --system >/dev/null 2>&1
    
    echo -e "${GREEN}✅ 系统优化完成${NC}"
}

# ========= 安装依赖 =========
install_dependencies() {
    echo -e "${YELLOW}📦 检查并安装必要依赖...${NC}"
    
    # 更新包列表
    apt update >/dev/null 2>&1
    
    # 安装必要软件
    PACKAGES="shadowsocks-libev qrencode curl jq net-tools iptables-persistent dnsutils ipset" # Added ipset
    for pkg in $PACKAGES; do
        if ! dpkg -l | grep -q "^ii[[:space:]]*$pkg"; then # More precise check
            echo -e "安装 $pkg..."
            if ! apt install -y $pkg >/dev/null 2>&1; then
                echo -e "${RED}❌ 错误：安装 $pkg 失败，请检查网络或软件源。${NC}"
                return 1
            fi
        fi
    done
    
    echo -e "${GREEN}✅ 依赖安装完成${NC}"
    return 0
}

# ========= 生成单个节点 =========
generate_node() {
    local node_index=$1
    local custom_tag=$2
    local method=$3
    local country=$4
    local use_warp=$5 # "true" or "false"
    
    # 生成随机端口和密码
    local port=$(shuf -i 20000-40000 -n 1)
    local password=$(openssl rand -base64 16)
    
    # 构建节点标签
    local flag="${COUNTRY_FLAGS[$country]:-🌍}"
    local warp_suffix=""
    [[ "$use_warp" == "true" ]] && warp_suffix="-WARP"
    local tag="${flag} ${custom_tag:-$DEFAULT_TAG}-${node_index}${warp_suffix}"
    
    # 创建配置目录
    mkdir -p /etc/shadowsocks-libev
    
    # 创建配置文件
    local config_file="/etc/shadowsocks-libev/config_${node_index}.json"
    
    if [[ "$use_warp" == "true" ]]; then
        # WARP 模式配置
        cat > "$config_file" <<EOF
{
    "server": "::",
    "server_port": $port,
    "password": "$password",
    "timeout": 300,
    "method": "$method",
    "mode": "tcp_and_udp",
    "fast_open": true,
    "no_delay": true,
    "reuse_port": true,
    "outbound_bind_interface": "warp"
}
EOF
    else
        # 标准配置
        cat > "$config_file" <<EOF
{
    "server": "::",
    "server_port": $port,
    "password": "$password",
    "timeout": 300,
    "method": "$method",
    "mode": "tcp_and_udp",
    "fast_open": true,
    "no_delay": true,
    "reuse_port": true,
    "nameserver": "8.8.8.8,1.1.1.1"
}
EOF
    fi
    
    # 创建 systemd 服务
    cat > "/etc/systemd/system/shadowsocks-libev-${node_index}.service" <<EOF
[Unit]
Description=Shadowsocks-libev Server ${node_index}
After=network.target

[Service]
Type=simple
User=nobody
Group=nogroup
LimitNOFILE=1000000
ExecStart=/usr/bin/ss-server -c ${config_file}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    
    # 启动服务
    systemctl daemon-reload
    systemctl enable "shadowsocks-libev-${node_index}" >/dev/null 2>&1
    systemctl restart "shadowsocks-libev-${node_index}"
    
    # 生成节点信息
    # Ensure IPV6_ADDR is set
    local current_ipv6_addr=""
    current_ipv6_addr=$(ip -6 addr show scope global | grep inet6 | grep -v "temporary" | awk '{print $2}' | cut -d/ -f1 | head -n1)
    if [ -z "$current_ipv6_addr" ]; then
        echo -e "${RED}错误：无法获取IPv6地址来生成SS链接。${NC}" >&2
        return 1
    fi

    local encoded=$(echo -n "$method:$password@[$current_ipv6_addr]:$port" | base64 -w 0)
    local ss_link="ss://$encoded#$(echo -n "$tag" | jq -sRr @uri)"
    
    # 返回 JSON
    echo "{
        \"index\": $node_index,
        \"tag\": \"$tag\",
        \"server\": \"$current_ipv6_addr\",
        \"port\": $port,
        \"password\": \"$password\",
        \"method\": \"$method\",
        \"ss_link\": \"$ss_link\",
        \"use_warp\": $use_warp
    }"
}

# ========= 生成 Clash 订阅 =========
generate_clash_subscribe() {
    local nodes_json=$1
    
    mkdir -p "$(dirname "$CLASH_CONFIG")"
    
    # Clash 配置头部
    cat > "$CLASH_CONFIG" <<EOF
# Shadowsocks IPv6 Clash 订阅
# 生成时间: $(date)
# 优化场景: 游戏/外贸/社媒/工作
# 版本: $SCRIPT_VERSION

port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090

# DNS 配置（优化游戏延迟）
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 119.29.29.29
    - 223.5.5.5
    - 8.8.8.8
    - 1.1.1.1
  fallback:
    - https://dns.google/dns-query
    - https://cloudflare-dns.com/dns-query

# 代理节点
proxies:
EOF
    
    # 添加节点
    echo "$nodes_json" | jq -r '.[] | "  - { name: \"\(.tag)\", type: ss, server: \"[\(.server)]\", port: \(.port), cipher: \"\(.method)\", password: \"\(.password)\", udp: true }"' >> "$CLASH_CONFIG"
    
    # 代理组
    cat >> "$CLASH_CONFIG" <<EOF

# 代理组配置
proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies:
EOF
    echo "$nodes_json" | jq -r '.[] | "      - \"\(.tag)\""' >> "$CLASH_CONFIG"
    echo "      - DIRECT" >> "$CLASH_CONFIG"
    
    # 游戏加速组
    cat >> "$CLASH_CONFIG" <<EOF

  - name: "🎮 游戏加速"
    type: select
    proxies:
EOF
    # 优先显示 WARP 节点
    echo "$nodes_json" | jq -r '.[] | select(.use_warp == true) | "      - \"\(.tag)\""' >> "$CLASH_CONFIG"
    echo "$nodes_json" | jq -r '.[] | select(.use_warp != true) | "      - \"\(.tag)\""' >> "$CLASH_CONFIG"
    
    # 其他代理组
    cat >> "$CLASH_CONFIG" <<EOF

  - name: "📺 国际媒体"
    type: select
    proxies:
EOF
    echo "$nodes_json" | jq -r '.[] | "      - \"\(.tag)\""' >> "$CLASH_CONFIG"
    
    cat >> "$CLASH_CONFIG" <<EOF

  - name: "🌍 国外网站"
    type: select
    proxies:
EOF
    echo "$nodes_json" | jq -r '.[] | "      - \"\(.tag)\""' >> "$CLASH_CONFIG"
    
    # 规则配置
    cat >> "$CLASH_CONFIG" <<EOF

# 规则配置
rules:
  # 游戏规则（Ingress/Pokemon GO）
  - DOMAIN-SUFFIX,nianticlabs.com,🎮 游戏加速
  - DOMAIN-SUFFIX,pokemon.com,🎮 游戏加速
  - DOMAIN-SUFFIX,pokemongo.com,🎮 游戏加速
  - DOMAIN-SUFFIX,unity3d.com,🎮 游戏加速
  - DOMAIN,pgorelease.nianticlabs.com,🎮 游戏加速
  - DOMAIN,sso.pokemon.com,🎮 游戏加速
  - IP-CIDR,35.0.0.0/8,🎮 游戏加速
  - IP-CIDR,52.0.0.0/8,🎮 游戏加速
  - IP-CIDR,130.211.0.0/16,🎮 游戏加速 # Google Cloud range often used by Niantic

  # 社交媒体
  - DOMAIN-SUFFIX,facebook.com,🌍 国外网站
  - DOMAIN-SUFFIX,twitter.com,🌍 国外网站
  - DOMAIN-SUFFIX,instagram.com,🌍 国外网站
  - DOMAIN-SUFFIX,youtube.com,📺 国际媒体
  - DOMAIN-SUFFIX,netflix.com,📺 国际媒体
  
  # 外贸常用
  - DOMAIN-SUFFIX,google.com,🌍 国外网站
  - DOMAIN-SUFFIX,gmail.com,🌍 国外网站
  - DOMAIN-SUFFIX,linkedin.com,🌍 国外网站
  - DOMAIN-SUFFIX,whatsapp.com,🌍 国外网站
  
  # 国内直连
  - DOMAIN-SUFFIX,cn,DIRECT
  - DOMAIN-KEYWORD,china,DIRECT
  - GEOIP,CN,DIRECT
  
  # 最终规则
  - MATCH,🚀 节点选择
EOF
}

# ========= WARP 安装函数 =========
install_warp() {
    print_banner
    echo -e "${YELLOW}🚀 开始安装 Cloudflare WARP...${NC}\n"
    
    # 检查系统
    if ! command -v lsb_release &> /dev/null; then
        apt-get update && apt-get install -y lsb-release
    fi
    
    # Check if already installed
    if command -v warp-cli &> /dev/null; then
        echo -e "${GREEN}✅ WARP 已安装${NC}"
        warp-cli --version
        echo ""
        
        # Check connection status
        if warp-cli status 2>/dev/null | grep -q "Connected"; then
            echo -e "${GREEN}WARP 已连接${NC}"
            read -p "是否重新配置？(y/n): " reconfigure
            if [[ "$reconfigure" != "y" ]]; then
                return 0 # Exit successfully if not reconfiguring
            fi
        fi
    fi
    
    # Install WARP
    echo -e "${YELLOW}添加 Cloudflare 仓库...${NC}"
    
    # First, install necessary tools
    apt update -y
    apt install -y curl gnupg lsb-release
    
    # Add GPG key
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    
    # Add repository
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
    
    # Update and install
    apt update -y
    if ! apt install -y cloudflare-warp; then
        echo -e "${RED}❌ WARP 安装失败，请检查网络连接或系统兼容性。${NC}"
        read -p "按回车键返回主菜单..."
        return 1
    fi
    
    # Start service
    systemctl enable warp-svc
    systemctl start warp-svc
    
    # Wait for service to start
    sleep 3
    
    # Configure WARP
    echo -e "${YELLOW}配置 WARP...${NC}"
    
    # Disconnect any existing connection
    warp-cli disconnect 2>/dev/null || true
    
    # --- OPTIMIZATION START ---
    # Register (using yes to auto-confirm if prompted by older versions, though 'registration' is usually silent)
    echo "y" | warp-cli registration new || true # Corrected: 'register' to 'registration new'
    
    # Set to proxy mode
    warp-cli set-mode proxy || true # This command might still be valid, or could be part of 'proxy' subcommand. Keeping for now.
    
    # Set proxy port
    warp-cli proxy set-port 40000 || true # Corrected: 'set-proxy-port' to 'proxy set-port'
    
    # Set other options (these commands might have been removed or changed significantly)
    # They are often not critical for basic proxy functionality.
    # It's safer to remove or comment out commands that cause "unrecognized subcommand" errors
    # unless you can find their direct replacements in the current warp-cli documentation.
    # If these are desired, you'll need to check current `warp-cli --help` for equivalents.
    # warp-cli set-families-mode off # Likely removed or changed, remove for stability
    # warp-cli set-dns-log-enabled false # Likely removed or changed, remove for stability
    # --- OPTIMIZATION END ---

    # Connect
    echo -e "${YELLOW}连接 WARP...${NC}"
    warp-cli connect
    
    # Wait for connection
    echo -n "等待连接"
    local connected=false
    for i in {1..15}; do # Increased wait time
        if warp-cli status 2>/dev/null | grep -q "Connected"; then
            echo -e " ${GREEN}成功！${NC}"
            connected=true
            break
        fi
        echo -n "."
        sleep 1
    done
    
    # Verify connection
    echo -e "\n${YELLOW}验证 WARP 连接...${NC}"
    if [[ "$connected" == true ]] && curl --proxy socks5://127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace/ 2>/dev/null | grep -q "warp=on"; then
        echo -e "${GREEN}✅ WARP 连接成功！${NC}"
        
        # Test game connectivity
        echo -e "\n${YELLOW}测试游戏服务连通性（通过 WARP）...${NC}"
        response=$(curl --proxy socks5://127.0.0.1:40000 -s -o /dev/null -w "%{http_code}" "https://pgorelease.nianticlabs.com/plfe/version" --connect-timeout 5 2>/dev/null || echo "000")
        
        if [[ "$response" == "200" ]] || [[ "$response" == "301" ]] || [[ "$response" == "302" ]]; then
            echo -e "${GREEN}✅ 通过 WARP 可以访问游戏服务！${NC}"
        else
            echo -e "${YELLOW}⚠️ 游戏服务返回: $response （可能需要手动检查WARP状态）${NC}"
        fi
        
        # Create WARP routing rules (for SS)
        echo -e "\n${YELLOW}配置智能路由，确保游戏流量走 WARP...${NC}"
        
        # Create routing script
        mkdir -p /etc/shadowsocks/
        cat > /etc/shadowsocks/warp_route.sh <<'EOF'
#!/bin/bash
# WARP Smart Route script

# Create ipset
ipset create niantic_ips hash:net 2>/dev/null || true

# Flush existing rules
iptables -t mangle -F WARP_MARK 2>/dev/null || true
ip rule del fwmark 1 table 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true

# Add Niantic IP ranges (more comprehensive Niantic/Google Cloud IP ranges)
# Ensure these are still current and relevant
ipset add niantic_ips 35.184.0.0/16 2>/dev/null || true
ipset add niantic_ips 35.192.0.0/12 2>/dev/null || true
ipset add niantic_ips 35.208.0.0/12 2>/dev/null || true
ipset add niantic_ips 35.224.0.0/11 2>/dev/null || true
ipset add niantic_ips 35.240.0.0/12 2>/dev/null || true
ipset add niantic_ips 52.0.0.0/8 2>/dev/null || true # Broader range if needed, be careful
ipset add niantic_ips 130.211.0.0/16 2>/dev/null || true
ipset add niantic_ips 104.18.0.0/15 2>/dev/null || true # Cloudflare for some Niantic assets

# Mark traffic that needs to go through WARP
iptables -t mangle -N WARP_MARK 2>/dev/null || true
iptables -t mangle -F WARP_MARK
iptables -t mangle -A WARP_MARK -m set --match-set niantic_ips dst -j MARK --set-mark 1

# Apply rule
iptables -t mangle -A OUTPUT -j WARP_MARK

# Configure routing table
ip rule add fwmark 1 table 100 2>/dev/null || true
ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true # Route marked packets to localhost for WARP proxy
EOF
        
        chmod +x /etc/shadowsocks/warp_route.sh
        
        # Create systemd service
        cat > /etc/systemd/system/warp-route.service <<EOF
[Unit]
Description=WARP Smart Route for Niantic Games
After=network.target warp-svc.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/etc/shadowsocks/warp_route.sh
ExecStop=/sbin/iptables -t mangle -F WARP_MARK ; /sbin/ip rule del fwmark 1 table 100 ; /sbin/ip route flush table 100 ; ipset destroy niantic_ips 2>/dev/null || true

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable warp-route
        systemctl start warp-route
        
        echo -e "${GREEN}✅ WARP 安装配置完成！${NC}"
        echo -e "\n${CYAN}WARP 信息：${NC}"
        echo "代理地址: socks5://127.0.0.1:40000"
        echo "状态: $(warp-cli status 2>/dev/null | grep Status | awk '{print $2}')"
        echo -e "\n${YELLOW}现在可以创建使用 WARP 出口的 Shadowsocks 节点了！${NC}"
        return 0 # WARP installed and configured successfully
    else
        echo -e "${RED}❌ WARP 连接失败${NC}"
        echo "请检查："
        echo "1. 网络连接是否正常"
        echo "2. 系统是否支持 WARP (Debian/Ubuntu x86_64)"
        echo "3. 尝试手动运行: warp-cli connect"
        read -p "按回车键返回主菜单..."
        return 1 # WARP installation/connection failed
    fi
}

# ========= 部署 Shadowsocks =========
deploy_shadowsocks() {
    print_banner
    echo -e "${YELLOW}🚀 开始部署 Shadowsocks 节点${NC}\n"
    
    # 检查 IPv6
    if ! check_ipv6; then
        read -p "按回车键返回主菜单..."
        return
    fi
    
    # 询问配置
    echo -e "${CYAN}请输入要生成的节点数量 (推荐 1-3，默认 1): ${NC}"
    read -p "> " node_count
    node_count=${node_count:-1}
    [[ $node_count -lt 1 || $node_count -gt 10 ]] && node_count=1
    
    echo -e "${CYAN}请输入节点备注前缀 (默认: SS-IPv6): ${NC}"
    read -p "> " custom_tag
    custom_tag=${custom_tag:-$DEFAULT_TAG}
    
    echo -e "${CYAN}请选择加密方式:${NC}"
    echo "1) chacha20-ietf-poly1305 (推荐，游戏优化)"
    echo "2) aes-256-gcm (高安全性)"
    echo "3) aes-128-gcm (高性能)"
    read -p "> " method_choice
    method=${METHODS[$((method_choice-1))]}
    method=${method:-${METHODS[0]}}
    
    echo -e "${CYAN}请输入国家/地区代码 (如: US, JP, SG, 默认 US): ${NC}"
    read -p "> " country
    country=${country:-"US"}
    
    # 检查 WARP
    use_warp_for_node=false
    if command -v warp-cli &> /dev/null && warp-cli status 2>/dev/null | grep -q "Connected"; then
        echo -e "\n${GREEN}检测到 WARP 已安装并连接${NC}"
        read -p "是否创建至少一个使用 WARP 出口的节点？(y/n, 强烈推荐游戏用户选择 y): " use_warp_choice
        [[ "$use_warp_choice" == "y" ]] && use_warp_for_node=true
    else
        echo -e "\n${YELLOW}未检测到 WARP 或 WARP 未连接。如果您需要游戏加速，请先安装 WARP（主菜单选项 3）。${NC}"
    fi
    
    # 安装依赖
    if ! install_dependencies; then
        read -p "依赖安装失败，按回车键返回主菜单..."
        return
    fi
    
    # 系统优化
    optimize_system
    
    # 配置防火墙
    setup_firewall
    
    # 生成节点
    echo -e "\n${YELLOW}🔄 生成节点中...${NC}"
    nodes_json="["
    
    local first_node_is_warp=false
    if [[ "$use_warp_for_node" == true ]]; then
        node_info=$(generate_node 1 "$custom_tag" "$method" "$country" "true")
        if [ $? -ne 0 ]; then echo -e "${RED}❌ 节点 1 生成失败。${NC}"; read -p "按回车键返回主菜单..." ; return; fi
        nodes_json="${nodes_json}${node_info}"
        echo -e "${GREEN}✅ 节点 1 (WARP) 生成成功${NC}"
        first_node_is_warp=true
    fi

    for ((i=1; i<=node_count; i++)); do
        # If first node was WARP, skip index 1 and start from 2, ensuring only one WARP node for now
        if [[ "$first_node_is_warp" == true ]] && [[ $i -eq 1 ]]; then
            continue
        fi
        
        # Add comma if not the very first node being added
        if [[ "$nodes_json" != "[" ]]; then
            nodes_json="${nodes_json},"
        fi
        
        local current_index=$i
        if [[ "$first_node_is_warp" == true ]]; then
             current_index=$((i+1)) # Adjust index if WARP node was first
        fi

        # Ensure we don't exceed node_count total, considering the potentially already added WARP node
        if [[ "$first_node_is_warp" == true && $current_index -gt $((node_count+1)) ]]; then
            break
        fi
        if [[ "$first_node_is_warp" == false && $current_index -gt $node_count ]]; then
            break
        fi


        node_info=$(generate_node "$current_index" "$custom_tag" "$method" "$country" "false")
        if [ $? -ne 0 ]; then echo -e "${RED}❌ 节点 $current_index 生成失败。${NC}"; read -p "按回车键返回主菜单..." ; return; fi
        nodes_json="${nodes_json}${node_info}"
        echo -e "${GREEN}✅ 节点 $current_index 生成成功${NC}"
    done
    nodes_json="${nodes_json}]"
    
    # 保存节点信息
    mkdir -p "$(dirname "$NODES_INFO_FILE")"
    echo "$nodes_json" > "$NODES_INFO_FILE"
    
    # 生成 Clash 订阅
    generate_clash_subscribe "$nodes_json"
    
    # 显示结果
    display_nodes "$nodes_json"
    
    echo ""
    read -p "按回车键返回主菜单..."
}

# ========= 配置防火墙 =========
setup_firewall() {
    echo -e "${YELLOW}🔥 配置防火墙规则...${NC}"
    
    # Flush existing rules and set default policies to ACCEPT for easier management
    # (Note: In a production environment, you might want a stricter default policy)
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    ip6tables -P INPUT ACCEPT
    ip6tables -P FORWARD ACCEPT
    ip6tables -P OUTPUT ACCEPT

    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X

    ip6tables -F
    ip6tables -X
    ip6tables -t nat -F 2>/dev/null || true # nat table might not exist for ip6tables
    ip6tables -t nat -X 2>/dev/null || true
    ip6tables -t mangle -F
    ip6tables -t mangle -X

    # Allow established connections
    iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    ip6tables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    ip6tables -A INPUT -i lo -j ACCEPT

    # Allow SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # Allow Shadowsocks port range
    iptables -A INPUT -p tcp --dport 20000:40000 -j ACCEPT
    iptables -A INPUT -p udp --dport 20000:40000 -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 20000:40000 -j ACCEPT
    ip6tables -A INPUT -p udp --dport 20000:40000 -j ACCEPT
    
    # Allow WARP proxy port
    iptables -A INPUT -p tcp --dport 40000 -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 40000 -j ACCEPT

    # NAT rules for both IPv4 and IPv6 forwarding
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    
    # Save rules (for persistence across reboots)
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save >/dev/null 2>&1
        echo -e "${GREEN}✅ 防火墙规则已保存。${NC}"
    elif command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
        echo -e "${GREEN}✅ 防火墙规则已保存到 /etc/iptables/rules.v4 和 .v6。${NC}"
    else
        echo -e "${YELLOW}⚠️ 无法找到防火墙保存工具 (netfilter-persistent/iptables-save)。规则可能不会持久。${NC}"
    fi
    
    echo -e "${GREEN}✅ 防火墙配置完成${NC}"
}

# ========= 显示节点信息 =========
display_nodes() {
    local nodes_json=$1
    
    echo -e "\n${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         🎉 部署完成！节点信息如下         ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}\n"
    
    echo "$nodes_json" | jq -r '.[] | 
        "\n========= 节点 \(.index) =========\n" +
        "标签: \(.tag)\n" +
        "服务器: [\(.server)]\n" +
        "端口: \(.port)\n" +
        "密码: \(.password)\n" +
        "加密: \(.method)\n" +
        if .use_warp then "出口: WARP (游戏优化)\n" else "" end +
        "\nSS链接:\n\(.ss_link)\n"'
    
    # 生成二维码
    if command -v qrencode &> /dev/null; then
        echo -e "${CYAN}节点 1 二维码 (通常为 WARP 或主节点):${NC}"
        echo "$nodes_json" | jq -r '.[0].ss_link' | qrencode -t ANSIUTF8
    else
        echo -e "${YELLOW}💡 提示：安装 qrencode (sudo apt install qrencode) 可显示二维码。${NC}"
    fi
    
    echo -e "${PURPLE}📋 Clash 订阅文件路径: $CLASH_CONFIG${NC}"
    echo -e "${PURPLE}📋 节点信息文件路径: $NODES_INFO_FILE${NC}"
    
    # 如果有 Web 服务器
    local WEB_SERVER_URL=""
    if command -v nginx &> /dev/null; then
        WEB_SERVER_URL="nginx"
    elif command -v apache2 &> /dev/null; then
        WEB_SERVER_URL="apache2"
    fi

    if [ -n "$WEB_SERVER_URL" ]; then
        mkdir -p /var/www/html/sub 2>/dev/null
        cp "$CLASH_CONFIG" /var/www/html/sub/ 2>/dev/null
        echo -e "${PURPLE}🌐 Clash 订阅链接: http://[$IPV6_ADDR]/sub/clash_subscribe.yaml${NC}"
        echo -e "${YELLOW}请确保您的 $WEB_SERVER_URL 服务正在运行并允许访问 /sub 目录。${NC}"
    else
        echo -e "${YELLOW}⚠️ 未检测到 Nginx 或 Apache。Clash 订阅文件无法通过 Web 访问。${NC}"
    fi
    
    echo -e "\n${YELLOW}💡 使用提示:${NC}"
    echo "1. ${GREEN}游戏用户请优先使用带 ${BLUE}WARP${GREEN} 标记的节点${NC}，并在 Clash 中选择「🎮 游戏加速」策略组。"
    echo "2. 可通过 ${CYAN}systemctl status shadowsocks-libev-*${NC} 查看 Shadowsocks 服务状态。"
    echo "3. 如遇连接问题，请运行主菜单 ${CYAN}1. 检测 IP 质量${NC} 功能。"
}

# ========= 查看已部署节点 =========
view_nodes() {
    print_banner
    echo -e "${CYAN}📋 已部署节点信息${NC}\n"
    
    if [ -f "$NODES_INFO_FILE" ]; then
        nodes_json=$(cat "$NODES_INFO_FILE")
        display_nodes "$nodes_json"
    else
        echo -e "${YELLOW}暂无已部署的节点。请先执行部署操作。${NC}"
    fi
    
    echo ""
    read -p "按回车键返回主菜单..."
}

# ========= 一键优化部署 =========
one_click_deploy() {
    print_banner
    echo -e "${YELLOW}🚀 开始一键优化部署${NC}\n"
    echo "此功能将自动："
    echo "1. 检测 IP 质量和游戏可用性。"
    echo "2. 如果 IP 对游戏不友好，将自动安装 WARP 并创建 WARP 出口节点。"
    echo "3. 部署优化的 Shadowsocks 节点和 Clash 订阅。"
    echo ""
    read -p "是否继续？(y/n): " confirm
    
    if [[ "$confirm" != "y" ]]; then
        return
    fi
    
    # 检查 IPv6
    if ! check_ipv6; then
        echo -e "${RED}无法进行一键部署：本脚本需要IPv6地址。${NC}"
        echo -e "请确保您的VPS支持IPv6，或考虑更换支持IPv6的VPS提供商。${NC}"
        read -p "按回车键返回主菜单..."
        return
    fi

    # 安装依赖 (提前安装，以确保IP检测和WARP安装顺利)
    if ! install_dependencies; then
        read -p "依赖安装失败，按回车键返回主菜单..."
        return
    fi
    
    echo -e "\n${CYAN}步骤 1/3: 检测 IP 质量${NC}"
    sleep 2
    
    local GAME_BLOCKED_FOR_AUTO=false
    # More robust check for Niantic game connectivity directly
    response=$(curl -6 -s -o /dev/null -w "%{http_code}" "https://pgorelease.nianticlabs.com/plfe/version" --connect-timeout 5 2>/dev/null || echo "000")
    if [[ "$response" == "403" ]] || [[ "$response" == "000" ]]; then
        GAME_BLOCKED_FOR_AUTO=true
        echo -e "${RED}检测到 IP 被游戏封禁或无法连接。将尝试通过 WARP 解决。${NC}"
    else
        echo -e "${GREEN}IP 可用于游戏（初步判断）。${NC}"
    fi
    
    # 如果被封，安装 WARP
    local USE_WARP_FOR_DEPLOYMENT=false
    if [[ "$GAME_BLOCKED_FOR_AUTO" == true ]]; then
        echo -e "\n${CYAN}步骤 2/3: IP 质量不佳，开始安装 WARP...${NC}"
        if install_warp; then
            USE_WARP_FOR_DEPLOYMENT=true
        else
            echo -e "${RED}❌ WARP 安装或连接失败，将尝试不带 WARP 部署节点。${NC}"
        fi
    else
        echo -e "\n${CYAN}步骤 2/3: IP 质量良好，跳过 WARP 自动安装。${NC}"
        read -p "您的IP质量初步判定可用，但仍建议安装WARP作为备份。是否现在安装WARP？(y/n): " install_warp_now
        if [[ "$install_warp_now" == "y" ]]; then
            if install_warp; then
                USE_WARP_FOR_DEPLOYMENT=true
            fi
        fi
    fi
    
    # 部署节点
    echo -e "\n${CYAN}步骤 3/3: 部署 Shadowsocks 节点...${NC}"
    
    # 自动配置参数
    local node_count_to_deploy=1 # Default to 1 node
    local auto_custom_tag="Auto"
    local auto_method="chacha20-ietf-poly1305"
    local auto_country="US" # Default to US
    
    optimize_system
    setup_firewall
    
    nodes_json="["
    
    if [[ "$USE_WARP_FOR_DEPLOYMENT" == true ]]; then
        echo -e "${YELLOW}正在生成一个 WARP 出口节点...${NC}"
        local node_info=$(generate_node 1 "$auto_custom_tag" "$auto_method" "$auto_country" "true")
        if [ $? -ne 0 ]; then echo -e "${RED}❌ WARP节点生成失败。${NC}"; read -p "按回车键返回主菜单..." ; return; fi
        nodes_json="${nodes_json}${node_info}"
        echo -e "${GREEN}✅ WARP 出口节点 (编号 1) 生成成功。${NC}"
        node_count_to_deploy=2 # If WARP node is created, create one more regular node
    else
        echo -e "${YELLOW}正在生成一个标准节点...${NC}"
        local node_info=$(generate_node 1 "$auto_custom_tag" "$auto_method" "$auto_country" "false")
        if [ $? -ne 0 ]; then echo -e "${RED}❌ 标准节点生成失败。${NC}"; read -p "按回车键返回主菜单..." ; return; fi
        nodes_json="${nodes_json}${node_info}"
        echo -e "${GREEN}✅ 标准节点 (编号 1) 生成成功。${NC}"
    fi

    # If we created a WARP node, create one more standard node for diversity
    if [[ "$node_count_to_deploy" -eq 2 ]]; then
        nodes_json="${nodes_json},"
        echo -e "${YELLOW}正在生成另一个标准节点...${NC}"
        local node_info=$(generate_node 2 "$auto_custom_tag" "$auto_method" "$auto_country" "false")
        if [ $? -ne 0 ]; then echo -e "${RED}❌ 标准节点生成失败。${NC}"; read -p "按回车键返回主菜单..." ; return; fi
        nodes_json="${nodes_json}${node_info}"
        echo -e "${GREEN}✅ 标准节点 (编号 2) 生成成功。${NC}"
    fi

    nodes_json="${nodes_json}]"
    
    # 保存和显示
    echo "$nodes_json" > "$NODES_INFO_FILE"
    generate_clash_subscribe "$nodes_json"
    display_nodes "$nodes_json"
    
    echo -e "\n${GREEN}✅ 一键部署完成！${NC}"
    echo ""
    read -p "按回车键返回主菜单..."
}

# ========= 卸载功能 =========
uninstall_all() {
    print_banner
    echo -e "${RED}⚠️ 警告：此操作将卸载所有相关服务和配置！${NC}"
    echo "包括："
    echo "- 所有 Shadowsocks 节点服务及其配置文件"
    echo "- Cloudflare WARP 服务和客户端"
    echo "- WARP 智能路由脚本和规则"
    echo "- Clash 订阅文件和节点信息文件"
    echo "- 系统优化参数 (将还原 /etc/sysctl.conf)"
    echo "- 防火墙规则 (将清除相关规则)"
    echo ""
    read -p "确定要继续吗？(输入 'yes' 确认): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        echo "已取消卸载。"
        return
    fi
    
    echo -e "\n${YELLOW}开始卸载...${NC}"
    
    # 停止所有 SS 服务
    echo -e "${YELLOW}停止并禁用 Shadowsocks 服务...${NC}"
    for service in $(systemctl list-units --all --plain --no-legend | grep "shadowsocks-libev-.*\.service" | awk '{print $1}'); do
        systemctl stop "$service" 2>/dev/null
        systemctl disable "$service" 2>/dev/null
        echo -e "  - 停止并禁用 $service"
    done
    
    # 停止 WARP
    echo -e "${YELLOW}卸载 Cloudflare WARP...${NC}"
    if command -v warp-cli &> /dev/null; then
        warp-cli disconnect 2>/dev/null
        warp-cli delete 2>/dev/null
        apt purge -y cloudflare-warp 2>/dev/null
        echo -e "  - WARP 已卸载。"
    else
        echo -e "  - WARP 未安装。"
    fi

    # 清除 WARP 路由服务和规则
    echo -e "${YELLOW}清除 WARP 路由规则...${NC}"
    systemctl stop warp-route 2>/dev/null
    systemctl disable warp-route 2>/dev/null
    rm -f /etc/systemd/system/warp-route.service
    rm -f /etc/shadowsocks/warp_route.sh
    ipset destroy niantic_ips 2>/dev/null || true # Clean up ipset
    echo -e "  - WARP 路由规则已清除。"
    
    # 删除配置文件
    echo -e "${YELLOW}删除 Shadowsocks 和 Clash 配置文件...${NC}"
    rm -rf /etc/shadowsocks-libev
    rm -rf /etc/shadowsocks
    rm -f /etc/systemd/system/shadowsocks-libev-*.service
    echo -e "  - 配置文件已删除。"
    
    # 恢复系统优化参数 (可选，但建议)
    echo -e "${YELLOW}恢复系统优化参数...${NC}"
    if [ -f /etc/sysctl.conf.bak ]; then
        mv /etc/sysctl.conf.bak /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
        echo -e "  - /etc/sysctl.conf 已恢复。"
    fi
    rm -f /etc/sysctl.d/99-shadowsocks.conf
    echo -e "  - 自定义 sysctl 配置已删除。"

    # 清除防火墙规则 (仅清除由本脚本添加的部分)
    echo -e "${YELLOW}清除防火墙规则...${NC}"
    # This is a bit tricky to be perfectly clean without affecting user's other rules.
    # A simple flush might be too aggressive. Here we try to remove the specific chains/rules.
    # It's safer to just set default policy to ACCEPT and remove the specific rules if they exist.
    setup_firewall # Re-run to establish basic open rules, then remove specific ones.
    # After re-establishing a basic state with setup_firewall, manually remove specific rules if they were saved:
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save >/dev/null 2>&1 # Save current (cleaner) state
    elif command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
    fi
    echo -e "  - 防火墙规则已尝试清除或重置为默认ACCEPT。"

    # 重载 systemd
    systemctl daemon-reload
    systemctl reset-failed # Clear failed service units
    
    echo -e "${GREEN}✅ 所有相关服务和配置已成功卸载。${NC}"
    echo ""
    read -p "按回车键返回主菜单..."
}

# ========= 主函数 =========
main() {
    check_root
    
    while true; do
        print_banner
        print_menu
        
        read -p "请选择操作 [0-7]: " choice
        
        case $choice in
            1) check_ip_quality ;;
            2) deploy_shadowsocks ;;
            3) install_warp ;;
            4) one_click_deploy ;;
            5) view_nodes ;;
            6) optimize_system && echo -e "\n${GREEN}✅ 系统优化完成${NC}" && read -p "按回车键继续..." ;;
            7) uninstall_all ;;
            0) echo -e "${GREEN}感谢使用！再见！${NC}"; exit 0 ;;
            *) echo -e "${RED}无效选择，请重试${NC}"; sleep 2 ;;
        esac
    done
}

# 运行主程序
main

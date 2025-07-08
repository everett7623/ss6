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
║      Shadowsocks IPv6 全能优化脚本 v3.0         ║
║   集成 IP 检测 | WARP 支持 | 游戏优化           ║
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

check_ipv6() {
    IPV6_ADDR=$(ip -6 addr show scope global | grep inet6 | grep -v "temporary" | awk '{print $2}' | cut -d/ -f1 | head -n1)
    if [ -z "$IPV6_ADDR" ]; then
        echo -e "${RED}❌ 未检测到IPv6地址${NC}"
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
        echo -e "${RED}需要 IPv6 地址才能继续${NC}"
        read -p "按回车键返回主菜单..."
        return
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
    IS_BLOCKED=false
    
    for blocked in "${BLOCKED_ASNS[@]}"; do
        if [[ "$ASN" == "$blocked" ]]; then
            IS_BLOCKED=true
            echo -e "${RED}⚠️  警告: 此 IP 属于常被游戏封禁的 ASN${NC}"
            case $blocked in
                "AS16276") echo -e "${RED}   OVH - 大型数据中心，游戏检测严格${NC}" ;;
                "AS13335") echo -e "${RED}   Cloudflare - CDN 服务商${NC}" ;;
                "AS15169") echo -e "${RED}   Google Cloud - 云服务商${NC}" ;;
                "AS16509") echo -e "${RED}   Amazon AWS - 云服务商${NC}" ;;
                "AS14061") echo -e "${RED}   DigitalOcean - 云服务商${NC}" ;;
                "AS396982") echo -e "${RED}   Google Fiber - 商业网络${NC}" ;;
            esac
            break
        fi
    done
    
    if [[ "$IS_BLOCKED" == false ]]; then
        if echo "$ORG" | grep -iE "(residential|broadband|telecom|cable)" >/dev/null; then
            echo -e "${GREEN}✅ 可能是住宅 IP（游戏友好）${NC}"
        else
            echo -e "${YELLOW}⚠️  可能是数据中心 IP（需要测试）${NC}"
        fi
    fi
    
    # 测试 Niantic 服务
    echo -e "\n${CYAN}===== Niantic 服务连通性测试 =====${NC}"
    domains=(
        "pgorelease.nianticlabs.com"
        "sso.pokemon.com"
        "api.nianticlabs.com"
    )
    
    GAME_BLOCKED=false
    for domain in "${domains[@]}"; do
        echo -n "测试 $domain: "
        response=$(curl -6 -s -o /dev/null -w "%{http_code}" "https://$domain" --connect-timeout 5 2>/dev/null || echo "000")
        case $response in
            000) 
                echo -e "${RED}❌ 无法连接（网络错误或被封）${NC}"
                GAME_BLOCKED=true
                ;;
            403) 
                echo -e "${RED}❌ 403 Forbidden（IP 已被封禁）${NC}"
                GAME_BLOCKED=true
                ;;
            200|301|302) 
                echo -e "${GREEN}✅ 正常 (HTTP $response)${NC}"
                ;;
            *) 
                echo -e "${YELLOW}⚠️  异常响应 (HTTP $response)${NC}"
                ;;
        esac
    done
    
    # 测试其他游戏服务
    echo -e "\n${CYAN}===== 其他游戏平台测试 =====${NC}"
    echo -n "Steam: "
    curl -s -o /dev/null -w "%{http_code}" "https://store.steampowered.com" --connect-timeout 3 | \
        xargs -I {} sh -c 'if [ {} -eq 200 ]; then echo -e "'"${GREEN}"'✅ 正常'"${NC}"'"; else echo -e "'"${YELLOW}"'⚠️  异常 (HTTP {})'${NC}'"; fi'
    
    # 综合建议
    echo -e "\n${CYAN}===== 综合评估与建议 =====${NC}"
    if [[ "$GAME_BLOCKED" == true ]]; then
        echo -e "${RED}❌ 此 IP 不适合 Ingress/Pokemon GO${NC}"
        echo -e "\n建议采取以下措施："
        echo -e "1. ${YELLOW}使用 WARP 中转（选项 3）- 立即可用${NC}"
        echo -e "2. ${YELLOW}更换 VPS 提供商${NC}"
        echo -e "   ${GREEN}亚洲推荐:${NC}"
        echo -e "   - ConoHa VPS (日本本土)"
        echo -e "   - Sakura VPS (日本本土)"
        echo -e "   - RackNerd (美国，IP质量好)"
        echo -e "   ${GREEN}欧美推荐:${NC}"
        echo -e "   - BuyVM/Frantech (小众)"
        echo -e "   - Hetzner (德国)"
        echo -e "   - Contabo (德国，便宜)"
        echo -e "3. ${YELLOW}使用住宅代理服务${NC}"
        echo -e "\n${PURPLE}提示: 大部分主流VPS都被封禁，建议直接使用 WARP！${NC}"
    else
        echo -e "${GREEN}✅ IP 暂时可用于游戏${NC}"
        echo -e "\n注意事项："
        echo -e "1. 避免频繁切换地理位置"
        echo -e "2. 保持正常游戏行为"
        echo -e "3. 建议安装 WARP 作为备用"
    fi
    
    echo ""
    read -p "按回车键返回主菜单..."
}

# ========= 系统优化函数 =========
optimize_system() {
    echo -e "${YELLOW}🔧 正在进行系统优化...${NC}"
    
    # 备份原始配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak
    
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
    PACKAGES="shadowsocks-libev qrencode curl jq net-tools iptables-persistent dnsutils"
    for pkg in $PACKAGES; do
        if ! dpkg -l | grep -q "^ii  $pkg"; then
            echo -e "安装 $pkg..."
            apt install -y $pkg >/dev/null 2>&1
        fi
    done
    
    echo -e "${GREEN}✅ 依赖安装完成${NC}"
}

# ========= 生成单个节点 =========
generate_node() {
    local node_index=$1
    local custom_tag=$2
    local method=$3
    local country=$4
    local use_warp=$5
    
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
    local encoded=$(echo -n "$method:$password@[$IPV6_ADDR]:$port" | base64 -w 0)
    local ss_link="ss://$encoded#$(echo -n "$tag" | jq -sRr @uri)"
    
    # 返回 JSON
    echo "{
        \"index\": $node_index,
        \"tag\": \"$tag\",
        \"server\": \"$IPV6_ADDR\",
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
    
    # 检查是否已安装
    if command -v warp-cli &> /dev/null; then
        echo -e "${GREEN}✅ WARP 已安装${NC}"
        warp-cli --version
        echo ""
        
        # 检查连接状态
        if warp-cli status 2>/dev/null | grep -q "Connected"; then
            echo -e "${GREEN}WARP 已连接${NC}"
            read -p "是否重新配置？(y/n): " reconfigure
            if [[ "$reconfigure" != "y" ]]; then
                return
            fi
        fi
    fi
    
    # 安装 WARP
    echo -e "${YELLOW}添加 Cloudflare 仓库...${NC}"
    
    # 先安装必要的工具
    apt update
    apt install -y curl gnupg lsb-release
    
    # 添加 GPG key
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    
    # 添加仓库
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
    
    # 更新并安装
    apt update
    apt install -y cloudflare-warp
    
    # 启动服务
    systemctl enable warp-svc
    systemctl start warp-svc
    
    # 等待服务启动
    sleep 3
    
    # 配置 WARP
    echo -e "${YELLOW}配置 WARP...${NC}"
    
    # 断开可能的连接
    warp-cli disconnect 2>/dev/null || true
    
    # 注册（使用 yes 自动确认）
    yes | warp-cli register || true
    
    # 设置为代理模式
    warp-cli set-mode proxy
    warp-cli set-proxy-port 40000
    
    # 设置其他选项
    warp-cli set-families-mode off
    warp-cli set-dns-log-enabled false
    
    # 连接
    echo -e "${YELLOW}连接 WARP...${NC}"
    warp-cli connect
    
    # 等待连接
    echo -n "等待连接"
    for i in {1..10}; do
        if warp-cli status 2>/dev/null | grep -q "Connected"; then
            echo -e " ${GREEN}成功！${NC}"
            break
        fi
        echo -n "."
        sleep 1
    done
    
    # 验证连接
    echo -e "\n${YELLOW}验证 WARP 连接...${NC}"
    if curl --proxy socks5://127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace/ 2>/dev/null | grep -q "warp=on"; then
        echo -e "${GREEN}✅ WARP 连接成功！${NC}"
        
        # 测试游戏连通性
        echo -e "\n${YELLOW}测试游戏服务连通性...${NC}"
        response=$(curl --proxy socks5://127.0.0.1:40000 -s -o /dev/null -w "%{http_code}" "https://pgorelease.nianticlabs.com/plfe/version" --connect-timeout 5 2>/dev/null || echo "000")
        
        if [[ "$response" == "200" ]] || [[ "$response" == "301" ]] || [[ "$response" == "302" ]]; then
            echo -e "${GREEN}✅ 通过 WARP 可以访问游戏服务！${NC}"
        else
            echo -e "${YELLOW}⚠️  游戏服务返回: $response${NC}"
        fi
        
        # 创建 WARP 路由规则（用于 SS）
        echo -e "\n${YELLOW}配置智能路由...${NC}"
        
        # 创建路由脚本
        cat > /etc/shadowsocks/warp_route.sh <<'EOF'
#!/bin/bash
# WARP 智能路由脚本

# 创建 ipset
ipset create niantic_ips hash:net 2>/dev/null || true

# 添加 Niantic IP 段
ipset add niantic_ips 35.0.0.0/8 2>/dev/null || true
ipset add niantic_ips 52.0.0.0/8 2>/dev/null || true
ipset add niantic_ips 130.211.0.0/16 2>/dev/null || true

# 标记需要走 WARP 的流量
iptables -t mangle -N WARP_MARK 2>/dev/null || true
iptables -t mangle -F WARP_MARK
iptables -t mangle -A WARP_MARK -m set --match-set niantic_ips dst -j MARK --set-mark 1

# 应用规则
iptables -t mangle -A OUTPUT -j WARP_MARK

# 配置路由表
ip rule add fwmark 1 table 100 2>/dev/null || true
ip route add default via 127.0.0.1 dev lo table 100 2>/dev/null || true
EOF
        
        chmod +x /etc/shadowsocks/warp_route.sh
        
        # 创建 systemd 服务
        cat > /etc/systemd/system/warp-route.service <<EOF
[Unit]
Description=WARP Smart Route
After=network.target warp-svc.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/etc/shadowsocks/warp_route.sh

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable warp-route
        systemctl start warp-route
        
        echo -e "${GREEN}✅ WARP 安装配置完成！${NC}"
        echo -e "\n${CYAN}WARP 信息：${NC}"
        echo "代理地址: socks5://127.0.0.1:40000"
        echo "状态: $(warp-cli status | grep Status | awk '{print $2}')"
        echo -e "\n${YELLOW}现在可以创建使用 WARP 出口的节点了！${NC}"
    else
        echo -e "${RED}❌ WARP 连接失败${NC}"
        echo "请检查："
        echo "1. 网络连接是否正常"
        echo "2. 系统是否支持 WARP"
        echo "3. 尝试手动运行: warp-cli connect"
    fi
    
    echo ""
    read -p "按回车键返回主菜单..."
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
    echo -e "${CYAN}请输入要生成的节点数量 (1-10): ${NC}"
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
    
    echo -e "${CYAN}请输入国家/地区代码 (如: US, JP, SG): ${NC}"
    read -p "> " country
    country=${country:-"US"}
    
    # 检查 WARP
    use_warp=false
    if command -v warp-cli &> /dev/null && warp-cli status 2>/dev/null | grep -q "Connected"; then
        echo -e "\n${GREEN}检测到 WARP 已安装并连接${NC}"
        read -p "是否创建使用 WARP 出口的节点？(y/n): " use_warp_choice
        [[ "$use_warp_choice" == "y" ]] && use_warp=true
    fi
    
    # 安装依赖
    install_dependencies
    
    # 系统优化
    optimize_system
    
    # 配置防火墙
    setup_firewall
    
    # 生成节点
    echo -e "\n${YELLOW}🔄 生成节点中...${NC}"
    nodes_json="["
    
    for ((i=1; i<=node_count; i++)); do
        # 如果选择了 WARP，第一个节点使用 WARP
        if [[ "$use_warp" == true ]] && [[ $i -eq 1 ]]; then
            node_info=$(generate_node $i "$custom_tag" "$method" "$country" "true")
        else
            node_info=$(generate_node $i "$custom_tag" "$method" "$country" "false")
        fi
        nodes_json="${nodes_json}${node_info}"
        [[ $i -lt $node_count ]] && nodes_json="${nodes_json},"
        echo -e "${GREEN}✅ 节点 $i 生成成功${NC}"
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
    
    # IPv4 和 IPv6 规则
    for cmd in iptables ip6tables; do
        # 允许 SSH
        $cmd -A INPUT -p tcp --dport 22 -j ACCEPT
        
        # 允许 Shadowsocks 端口范围
        $cmd -A INPUT -p tcp --dport 20000:40000 -j ACCEPT
        $cmd -A INPUT -p udp --dport 20000:40000 -j ACCEPT
        
        # 允许 WARP
        $cmd -A INPUT -p tcp --dport 40000 -j ACCEPT
    done
    
    # NAT 规则
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    
    # 保存规则
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save >/dev/null 2>&1
    fi
    
    echo -e "${GREEN}✅ 防火墙配置完成${NC}"
}

# ========= 显示节点信息 =========
display_nodes() {
    local nodes_json=$1
    
    echo -e "\n${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         🎉 部署完成！节点信息如下        ║${NC}"
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
        echo -e "${CYAN}节点 1 二维码:${NC}"
        echo "$nodes_json" | jq -r '.[0].ss_link' | qrencode -t ANSIUTF8
    fi
    
    echo -e "${PURPLE}📋 Clash 订阅文件: $CLASH_CONFIG${NC}"
    echo -e "${PURPLE}📋 节点信息文件: $NODES_INFO_FILE${NC}"
    
    # 如果有 Web 服务器
    if command -v nginx &> /dev/null || command -v apache2 &> /dev/null; then
        mkdir -p /var/www/html/sub 2>/dev/null
        cp "$CLASH_CONFIG" /var/www/html/sub/ 2>/dev/null
        echo -e "${PURPLE}🌐 Clash 订阅链接: http://[$IPV6_ADDR]/sub/clash_subscribe.yaml${NC}"
    fi
    
    echo -e "\n${YELLOW}💡 使用提示:${NC}"
    echo "1. 游戏用户请优先使用带 WARP 标记的节点"
    echo "2. Clash 用户请使用「游戏加速」策略组"
    echo "3. 可通过 systemctl status shadowsocks-libev-* 查看服务状态"
    echo "4. 如遇连接问题，请运行 IP 检测功能"
}

# ========= 查看已部署节点 =========
view_nodes() {
    print_banner
    echo -e "${CYAN}📋 已部署节点信息${NC}\n"
    
    if [ -f "$NODES_INFO_FILE" ]; then
        nodes_json=$(cat "$NODES_INFO_FILE")
        display_nodes "$nodes_json"
    else
        echo -e "${YELLOW}暂无已部署的节点${NC}"
    fi
    
    echo ""
    read -p "按回车键返回主菜单..."
}

# ========= 一键优化部署 =========
one_click_deploy() {
    print_banner
    echo -e "${YELLOW}🚀 开始一键优化部署${NC}\n"
    echo "此功能将自动："
    echo "1. 检测 IP 质量"
    echo "2. 如果 IP 被封，自动安装 WARP"
    echo "3. 部署优化的 Shadowsocks 节点"
    echo ""
    read -p "是否继续？(y/n): " confirm
    
    if [[ "$confirm" != "y" ]]; then
        return
    fi
    
    # 检测 IP
    echo -e "\n${CYAN}步骤 1/3: 检测 IP 质量${NC}"
    sleep 2
    
    # 检查游戏可用性
    GAME_AVAILABLE=true
    response=$(curl -6 -s -o /dev/null -w "%{http_code}" "https://pgorelease.nianticlabs.com/plfe/version" --connect-timeout 5 2>/dev/null || echo "000")
    if [[ "$response" == "403" ]] || [[ "$response" == "000" ]]; then
        GAME_AVAILABLE=false
        echo -e "${RED}检测到 IP 被游戏封禁${NC}"
    else
        echo -e "${GREEN}IP 可用于游戏${NC}"
    fi
    
    # 如果被封，安装 WARP
    if [[ "$GAME_AVAILABLE" == false ]]; then
        echo -e "\n${CYAN}步骤 2/3: 安装 WARP${NC}"
        install_warp
        
        # 设置使用 WARP
        USE_WARP_DEFAULT=true
    else
        echo -e "\n${CYAN}步骤 2/3: 跳过 WARP 安装（IP 正常）${NC}"
        USE_WARP_DEFAULT=false
    fi
    
    # 部署节点
    echo -e "\n${CYAN}步骤 3/3: 部署 Shadowsocks${NC}"
    
    # 自动配置
    node_count=3  # 生成3个节点
    custom_tag="Auto"
    method="chacha20-ietf-poly1305"
    country="US"
    
    # 安装依赖
    install_dependencies
    optimize_system
    setup_firewall
    
    # 生成节点
    nodes_json="["
    for ((i=1; i<=node_count; i++)); do
        # 第一个节点使用 WARP（如果需要）
        if [[ "$USE_WARP_DEFAULT" == true ]] && [[ $i -eq 1 ]]; then
            node_info=$(generate_node $i "$custom_tag" "$method" "$country" "true")
        else
            node_info=$(generate_node $i "$custom_tag" "$method" "$country" "false")
        fi
        nodes_json="${nodes_json}${node_info}"
        [[ $i -lt $node_count ]] && nodes_json="${nodes_json},"
    done
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
    echo -e "${RED}⚠️  警告：此操作将卸载所有服务${NC}"
    echo "包括："
    echo "- 所有 Shadowsocks 节点"
    echo "- Cloudflare WARP"
    echo "- 相关配置文件"
    echo ""
    read -p "确定要继续吗？(yes/no): " confirm
    
    if [[ "$confirm" != "yes" ]]; then
        echo "已取消"
        return
    fi
    
    echo -e "\n${YELLOW}开始卸载...${NC}"
    
    # 停止所有 SS 服务
    systemctl stop shadowsocks-libev-* 2>/dev/null
    systemctl disable shadowsocks-libev-* 2>/dev/null
    
    # 停止 WARP
    if command -v warp-cli &> /dev/null; then
        warp-cli disconnect 2>/dev/null
        warp-cli delete 2>/dev/null
        apt remove -y cloudflare-warp 2>/dev/null
    fi
    
    # 删除配置文件
    rm -rf /etc/shadowsocks-libev
    rm -rf /etc/shadowsocks
    rm -f /etc/systemd/system/shadowsocks-libev-*.service
    rm -f /etc/systemd/system/warp-route.service
    
    # 重载 systemd
    systemctl daemon-reload
    
    echo -e "${GREEN}✅ 卸载完成${NC}"
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

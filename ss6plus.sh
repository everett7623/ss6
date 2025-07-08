#!/bin/bash
# ========================================
# Shadowsocks IPv6 全能优化部署脚本 v2.0
# 支持外贸/社媒/娱乐/工作/游戏等场景
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
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════╗"
    echo "║    Shadowsocks IPv6 优化部署脚本 v2.0    ║"
    echo "║         支持游戏/外贸/社媒全场景         ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
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
        echo -e "${RED}❌ 未检测到IPv6地址，脚本退出${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ 检测到IPv6地址: $IPV6_ADDR${NC}"
}

# 系统优化函数（针对游戏和高性能需求）
optimize_system() {
    echo -e "${YELLOW}🔧 正在进行系统优化...${NC}"
    
    # 1. 开启 BBR 拥塞控制
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    
    # 2. 优化网络参数（特别针对游戏）
    cat >> /etc/sysctl.conf <<EOF
# 游戏优化参数
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_frto = 2
net.ipv4.tcp_low_latency = 1

# IPv6 优化
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
net.ipv6.conf.all.use_tempaddr = 0
net.ipv6.conf.default.use_tempaddr = 0

# 内存和连接数优化
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 60000
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30

# UDP 优化（Ingress 游戏需要）
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
    
    # 3. 优化文件描述符限制
    cat >> /etc/security/limits.conf <<EOF
* soft nofile 1000000
* hard nofile 1000000
* soft nproc 1000000
* hard nproc 1000000
EOF
    
    # 4. 应用系统参数
    sysctl -p >/dev/null 2>&1
    
    echo -e "${GREEN}✅ 系统优化完成${NC}"
}

# 安装必要软件
install_dependencies() {
    echo -e "${YELLOW}📦 安装必要依赖...${NC}"
    apt update >/dev/null 2>&1
    apt install -y shadowsocks-libev qrencode curl jq net-tools iptables-persistent >/dev/null 2>&1
    echo -e "${GREEN}✅ 依赖安装完成${NC}"
}

# 生成单个节点
generate_node() {
    local node_index=$1
    local custom_tag=$2
    local method=$3
    local country=$4
    
    # 生成随机端口和密码
    local port=$(shuf -i 20000-40000 -n 1)
    local password=$(openssl rand -base64 16)
    
    # 构建节点标签
    local flag="${COUNTRY_FLAGS[$country]:-🌍}"
    local tag="${flag} ${custom_tag:-$DEFAULT_TAG}-${node_index}"
    
    # 创建配置文件
    local config_file="/etc/shadowsocks-libev/config_${node_index}.json"
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
    "plugin": "",
    "plugin_opts": "",
    "nameserver": "8.8.8.8,1.1.1.1"
}
EOF
    
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
    
    # 保存节点信息
    echo "{
        \"index\": $node_index,
        \"tag\": \"$tag\",
        \"server\": \"$IPV6_ADDR\",
        \"port\": $port,
        \"password\": \"$password\",
        \"method\": \"$method\",
        \"ss_link\": \"$ss_link\"
    }"
}

# 生成 Clash 订阅文件
generate_clash_subscribe() {
    local nodes_json=$1
    
    mkdir -p "$(dirname "$CLASH_CONFIG")"
    
    # 生成 Clash 配置头部
    cat > "$CLASH_CONFIG" <<EOF
# Shadowsocks IPv6 Clash 订阅
# 生成时间: $(date)
# 优化场景: 游戏/外贸/社媒/工作

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
    
    # 添加节点到 Clash 配置
    echo "$nodes_json" | jq -r '.[] | "  - { name: \"\(.tag)\", type: ss, server: \"[\(.server)]\", port: \(.port), cipher: \"\(.method)\", password: \"\(.password)\", udp: true }"' >> "$CLASH_CONFIG"
    
    # 添加代理组
    cat >> "$CLASH_CONFIG" <<EOF

# 代理组配置
proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies:
EOF
    
    echo "$nodes_json" | jq -r '.[] | "      - \"\(.tag)\""' >> "$CLASH_CONFIG"
    
    cat >> "$CLASH_CONFIG" <<EOF
      - DIRECT

  - name: "🎮 游戏加速"
    type: select
    proxies:
EOF
    
    echo "$nodes_json" | jq -r '.[] | "      - \"\(.tag)\""' >> "$CLASH_CONFIG"
    
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
    
    # 添加规则
    cat >> "$CLASH_CONFIG" <<EOF

# 规则配置
rules:
  # 游戏规则（Ingress 等）
  - DOMAIN-SUFFIX,nianticlabs.com,🎮 游戏加速
  - DOMAIN-SUFFIX,pokemon.com,🎮 游戏加速
  - DOMAIN-SUFFIX,pokemongo.com,🎮 游戏加速
  - DOMAIN-SUFFIX,unity3d.com,🎮 游戏加速
  - IP-CIDR,35.0.0.0/8,🎮 游戏加速
  - IP-CIDR,52.0.0.0/8,🎮 游戏加速
  
  # 社交媒体
  - DOMAIN-SUFFIX,facebook.com,🌍 国外网站
  - DOMAIN-SUFFIX,twitter.com,🌍 国外网站
  - DOMAIN-SUFFIX,instagram.com,🌍 国外网站
  - DOMAIN-SUFFIX,youtube.com,📺 国际媒体
  
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
    
    echo -e "${GREEN}✅ Clash 订阅文件已生成: $CLASH_CONFIG${NC}"
}

# 配置防火墙规则（针对游戏优化）
setup_firewall() {
    echo -e "${YELLOW}🔥 配置防火墙规则...${NC}"
    
    # 允许 SSH
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # 允许 Shadowsocks 端口范围
    iptables -A INPUT -p tcp --dport 20000:40000 -j ACCEPT
    iptables -A INPUT -p udp --dport 20000:40000 -j ACCEPT
    ip6tables -A INPUT -p tcp --dport 20000:40000 -j ACCEPT
    ip6tables -A INPUT -p udp --dport 20000:40000 -j ACCEPT
    
    # 优化 UDP 转发（游戏需要）
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    
    # 保存规则
    netfilter-persistent save >/dev/null 2>&1
    
    echo -e "${GREEN}✅ 防火墙规则配置完成${NC}"
}

# 主函数
main() {
    clear
    print_banner
    check_root
    check_ipv6
    
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
    
    # 执行安装和优化
    install_dependencies
    optimize_system
    setup_firewall
    
    # 生成节点
    echo -e "${YELLOW}🚀 开始生成节点...${NC}"
    nodes_json="["
    for ((i=1; i<=node_count; i++)); do
        node_info=$(generate_node $i "$custom_tag" "$method" "$country")
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
    
    # 输出结果
    echo -e "\n${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         🎉 部署完成！节点信息如下        ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}\n"
    
    echo "$nodes_json" | jq -r '.[] | "\n========= 节点 \(.index) =========\n标签: \(.tag)\n服务器: [\(.server)]\n端口: \(.port)\n密码: \(.password)\n加密: \(.method)\n\nSS链接:\n\(.ss_link)\n"'
    
    echo -e "${PURPLE}📋 Clash 订阅文件: $CLASH_CONFIG${NC}"
    echo -e "${PURPLE}📋 节点信息文件: $NODES_INFO_FILE${NC}"
    
    # 生成订阅链接（如果有 Web 服务器）
    if command -v nginx &> /dev/null; then
        mkdir -p /var/www/html/sub
        cp "$CLASH_CONFIG" /var/www/html/sub/
        echo -e "${PURPLE}🌐 Clash 订阅链接: http://[$IPV6_ADDR]/sub/clash_subscribe.yaml${NC}"
    fi
    
    echo -e "\n${YELLOW}💡 使用提示:${NC}"
    echo "1. 游戏用户请使用 Clash 的游戏加速模式"
    echo "2. 外贸用户建议选择延迟最低的节点"
    echo "3. 可通过 systemctl status shadowsocks-libev-* 查看服务状态"
    echo "4. 如遇到游戏连接问题，请检查 UDP 转发是否正常"
}

# 运行主函数
main

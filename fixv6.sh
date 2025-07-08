#!/bin/bash
# IPv6 修复脚本

echo "开始修复 IPv6..."

# 1. 恢复 IPv6 默认设置
echo "恢复 IPv6 配置..."
sysctl -w net.ipv6.conf.all.disable_ipv6=0
sysctl -w net.ipv6.conf.default.disable_ipv6=0
sysctl -w net.ipv6.conf.lo.disable_ipv6=0

# 2. 清理可能有问题的 sysctl 配置
sed -i '/net.ipv6.conf.all.forwarding/d' /etc/sysctl.conf
sed -i '/net.ipv6.conf.default.forwarding/d' /etc/sysctl.conf

# 3. 重启网络接口
echo "重启网络接口..."
# 获取主网络接口名
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -n "$IFACE" ]; then
    ip link set $IFACE down
    ip link set $IFACE up
fi

# 4. 重启网络服务
echo "重启网络服务..."
if systemctl is-active --quiet NetworkManager; then
    systemctl restart NetworkManager
elif systemctl is-active --quiet systemd-networkd; then
    systemctl restart systemd-networkd
else
    systemctl restart networking
fi

# 5. 等待网络恢复
sleep 5

# 6. 检查 IPv6
echo "检查 IPv6 状态..."
IPV6_ADDR=$(ip -6 addr show scope global | grep inet6 | grep -v "temporary" | awk '{print $2}' | cut -d/ -f1 | head -n1)
if [ -n "$IPV6_ADDR" ]; then
    echo "✓ IPv6 已恢复: $IPV6_ADDR"
else
    echo "✗ IPv6 仍未恢复，请尝试重启服务器：reboot"
fi

# 7. 显示当前网络状态
echo -e "\n当前网络配置："
ip addr show | grep -E "inet6?.*scope global"

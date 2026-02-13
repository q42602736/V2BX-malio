#!/bin/bash

set -e

echo "开始构建 V2bX..."

# 清理旧文件
rm -rf build
mkdir -p build

# 编译 amd64 版本
echo "编译 Linux amd64 版本..."
GOOS=linux GOARCH=amd64 go build -tags "sing,xray,hysteria2,with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api" -o build/V2bX-amd64 -ldflags="-s -w" main.go

# 编译 arm64 版本
echo "编译 Linux arm64 版本..."
GOOS=linux GOARCH=arm64 go build -tags "sing,xray,hysteria2,with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api" -o build/V2bX-arm64 -ldflags="-s -w" main.go

# 下载 geoip 和 geosite 数据文件（如果不存在）
if [ ! -f "geoip.dat" ]; then
    echo "下载 geoip.dat..."
    curl -L -o geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
fi

if [ ! -f "geosite.dat" ]; then
    echo "下载 geosite.dat..."
    curl -L -o geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
fi

# 复制示例配置文件
echo "复制示例配置文件..."
cd build
cp ../geoip.dat .
cp ../geosite.dat .
cp ../example/geoip.db .
cp ../example/geosite.db .
cp ../example/config.json .
cp ../example/custom_inbound.json .
cp ../example/custom_outbound.json .
cp ../example/dns.json .
cp ../example/route.json .

# 打包 amd64 版本
echo "打包 amd64 版本..."
cp V2bX-amd64 V2bX
zip -q V2bX-linux-64.zip V2bX geoip.dat geosite.dat geoip.db geosite.db config.json custom_inbound.json custom_outbound.json dns.json route.json
rm V2bX

# 打包 arm64 版本
echo "打包 arm64 版本..."
cp V2bX-arm64 V2bX
zip -q V2bX-linux-arm64-v8a.zip V2bX geoip.dat geosite.dat geoip.db geosite.db config.json custom_inbound.json custom_outbound.json dns.json route.json
rm V2bX

# 清理临时文件
rm geoip.dat geosite.dat geoip.db geosite.db config.json custom_inbound.json custom_outbound.json dns.json route.json

cd ..

echo "构建完成！"
echo "文件位置："
ls -lh build/*.zip

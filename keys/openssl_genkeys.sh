#!/bin/bash

echo "========== 生成CA证书 =========="
# 生成CA私钥
openssl genrsa -out ca.key 2048
# 生成CA自签名证书
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=AA/ST=BB/L=CC/O=DD/OU=EE/CN=HUST"

echo "========== 生成服务器证书 =========="
# 生成服务器私钥
openssl genrsa -out server.key 2048
# 生成服务器证书请求
openssl req -new -key server.key -out server.csr \
  -subj "/C=GG/ST=HH/L=II/O=JJ/OU=KK/CN=cp.com"
# 用CA签名服务器证书
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt

echo "========== 生成客户端证书 =========="
# 生成客户端私钥
openssl genrsa -out client.key 2048
# 生成客户端证书请求
openssl req -new -key client.key -out client.csr \
  -subj "/C=MM/ST=NN/L=OO/O=PP/OU=QQ/CN=client"
# 用CA签名客户端证书
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt

echo "========== 生成PEM格式文件（包含私钥和证书） =========="
# 服务器PEM文件
cat server.crt server.key > server.pem
# 客户端PEM文件
cat client.crt client.key > client.pem

echo "========== 验证证书 =========="
openssl verify -CAfile ca.crt server.crt
openssl verify -CAfile ca.crt client.crt

echo "========== 生成完成！文件列表： =========="
ls -la *.crt *.key *.pem *.csr *.srl

echo "=========================================="
echo "重要文件："
echo "  CA证书: ca.crt"
echo "  服务器证书: server.crt"
echo "  服务器私钥: server.key"
echo "  服务器PEM: server.pem"
echo "  客户端证书: client.crt"
echo "  客户端私钥: client.key"
echo "  客户端PEM: client.pem"

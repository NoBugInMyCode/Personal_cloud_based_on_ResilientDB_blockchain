import hashlib
import json
import socket
import os
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import binascii
import hashlib

# 运行客户端
server_ip = '10.0.0.110'  # 服务器的IP地址
server_port = 5001  # 服务器的端口号
file_path = "C:/Users/29400/Desktop/ubuntu-22.04.3-desktop-amd64.iso"  # 要传输的文件路径


def _public_key_to_string(pub_key):
    """Convert an RSA public key type to string"""
    return pub_key.exportKey(format='PEM').decode('utf-8')


def _generate_key_pair(username: str, password: str):
    key = RSA.generate(2048)
    private_key = key.exportKey(passphrase=username + password, pkcs=8)
    public_key = key.publickey()
    public_key_str = _public_key_to_string(public_key)
    with open(f"private_key.pem", "wb") as f:
        f.write(private_key)
    return public_key_str


def sign_up(username: str, password: str):
    # 创建socket对象
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 连接到服务器
    client_socket.connect((server_ip, server_port))

    # 将数据转换为JSON格式
    json_data = json.dumps({"operation": "signup",
                            "username": username,
                            "password": password})

    # 发送JSON数据
    client_socket.sendall(json_data.encode())

    print(f"[*] Signup request sent to server")

    # 等待服务器端返回
    response_data = client_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)

    if response["checker_result"]:
        print("[+] Username check passed, generating RSA key pair.")
        pub_key_string = _generate_key_pair(username, password)
        print("[+] Key pair generated, please store private_key.pem in a safe place.")
        client_socket.sendall((json.dumps({"pub_key_str": pub_key_string})).encode())

        # 等待服务器端返回注册结果
        response_data = client_socket.recv(4096).decode('utf-8')
        response = json.loads(response_data)
        if response["signup_result"]:
            print("[+] Account as been created successfully, please login.")
    else:
        print("[!] Username has already taken, please choose another one.")


sign_up("aa", "123456")

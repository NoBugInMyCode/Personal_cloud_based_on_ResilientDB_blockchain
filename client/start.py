import hashlib
import json
import socket
import os

# 运行客户端
server_ip = '10.0.0.110'  # 服务器的IP地址
server_port = 5001  # 服务器的端口号
file_path = "C:/Users/29400/Desktop/ubuntu-22.04.3-desktop-amd64.iso"  # 要传输的文件路径


def _hash_with_sha256(input_string):
    """Hash a string with SHA256"""
    sha_signature = hashlib.sha256(input_string.encode()).hexdigest()
    return sha_signature


def send_command(data):
    # 创建socket对象
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 连接到服务器
    client_socket.connect((server_ip, server_port))

    # 将数据转换为JSON格式
    json_data = json.dumps(data)

    # 发送JSON数据
    client_socket.sendall(json_data.encode())

    # 关闭socket
    client_socket.close()
    print("[+] Data has been sent successfully.")


def sign_up(username: str, password: str):
    # 创建socket对象
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # 连接到服务器
    client_socket.connect((server_ip, server_port))

    # 将数据转换为JSON格式
    json_data = json.dumps({"operation": "signup",
                            "username": username,
                            "password": _hash_with_sha256(password)})

    # 发送JSON数据
    client_socket.sendall(json_data.encode())

    # 等待服务器端返回
    response_data = client_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)

    if response["result"]:
        print("[*] Sign up successfully, please login.")
    else:
        print("[*] Username has already taken, please choose another one.")


sign_up("test", "123456")

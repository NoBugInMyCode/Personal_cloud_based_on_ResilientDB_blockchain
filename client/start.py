import hashlib
import json
import socket
import os
import time

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import binascii
import hashlib
import threading

login_statue = False
running = False
# 运行客户端
server_ip = '10.0.0.110'  # 服务器的IP地址
server_port = 5001  # 服务器的端口号
file_path = "C:/Users/29400/Desktop/ubuntu-22.04.3-desktop-amd64.iso"  # 要传输的文件路径
# 创建socket对象
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# 连接到服务器
client_socket.connect((server_ip, server_port))
global_username = ""


def _public_key_to_string(pub_key):
    """Convert an RSA public key type to string"""
    return pub_key.exportKey(format='PEM').decode('utf-8')


def _extend_login_time():
    while running:
        client_socket.sendall((json.dumps({"operation": "extend", "username": global_username})).encode('utf-8'))
        time.sleep(3)


def _generate_key_pair(username: str, password: str):
    key = RSA.generate(2048)
    private_key = key.exportKey(passphrase=username + password, pkcs=8)
    public_key = key.publickey()
    public_key_str = _public_key_to_string(public_key)
    with open(f"private_key.pem", "wb") as f:
        f.write(private_key)
    return public_key_str


def sign_up(username: str, password: str):
    # 将数据转换为JSON格式
    json_data = json.dumps({"operation": "signup",
                            "username": username})

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


def log_in(username: str, password: str):
    # 发送登录请求
    client_socket.sendall((json.dumps({"operation": "login", "username": username})).encode('utf-8'))
    print("[*] Login request sent to server")

    # 等待服务器端返回用户是否存在
    response_data = client_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)

    # 查看服务器端返回的消息
    if not response['username_checker']:
        print("[+] User not exist")
        return

    # 等待服务器端返回密语
    response_data = client_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)
    print("[+] Received cipher from server")

    # 加载RSA私钥
    try:
        with open("private_key.pem", "rb") as f:
            private_key = RSA.import_key(f.read(), passphrase=username + password)
            print("[+] RSA private key load successfully")
    except Exception as e:
        print("[!] Error loading private key, wrong password.")
        return

    # 解密密语
    print("[+] Decrypting cipher and sending to server")
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encrypted_string_binary = binascii.unhexlify(response['encrypted_string'])

    # Decrypt
    decrypted_string = cipher_rsa.decrypt(encrypted_string_binary)

    # Convert decrypted bytes to string before sending back to server
    decrypted_string_str = decrypted_string.decode('ascii')
    client_socket.sendall((json.dumps({"decrypted_string": decrypted_string_str})).encode('utf-8'))

    # 等待服务器返回登陆状况
    response_data = client_socket.recv(4096).decode('utf-8')
    print("[+] Received login result from server")
    response = json.loads(response_data)

    # 查看登陆结果
    if response['login_result']:
        global global_username, running, login_statue
        running = True
        global_username = username
        print("[+] Login successfully")
        extend_thread = threading.Thread(target=_extend_login_time)
        extend_thread.start()
        login_statue = True
        return
    else:
        print("[+] Login failed(cipher does not match)")


def start_client():
    print("Welcome to ResDrive, a decentralized personal cloud based on ResilientDB")
    while True:
        if not login_statue:
            login_or_signup = input("ResChat>")
            login_or_signup = login_or_signup.split(" ")
            if login_or_signup[0] == "login":
                if len(login_or_signup) != 3:
                    print("Wrong login usage, please follow `login YOUR_USERNAME YOUR_PASSWORD` or use -h to see full "
                          "command")
                else:
                    log_in(login_or_signup[1], login_or_signup[2])
            elif login_or_signup[0] == "signup":
                if len(login_or_signup) != 3:
                    print("Wrong signup usage, please follow `signup YOUR_USERNAME YOUR_PASSWORD` or use -h to see full"
                          " command")
                else:
                    sign_up(login_or_signup[1], login_or_signup[2])
        else:
            command = input(global_username + "@ResDrive:~/")


start_client()

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
command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
extend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# 连接到服务器
command_socket.connect((server_ip, server_port))
extend_socket.connect((server_ip, 5002))
file_socket.connect((server_ip, 5003))
global_username = ""

current_dir = ""


def _public_key_to_string(pub_key):
    """Convert an RSA public key type to string"""
    return pub_key.exportKey(format='PEM').decode('utf-8')


def _extend_login_time():
    while running:
        extend_socket.sendall((json.dumps({"operation": "extend", "username": global_username})).encode('utf-8'))
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
    command_socket.sendall(json_data.encode())

    print(f"[*] Signup request sent to server")

    # 等待服务器端返回
    response_data = command_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)

    if response["checker_result"]:
        print("[+] Username check passed, generating RSA key pair.")
        pub_key_string = _generate_key_pair(username, password)
        print("[+] Key pair generated, please store private_key.pem in a safe place.")
        command_socket.sendall((json.dumps({"pub_key_str": pub_key_string})).encode())

        # 等待服务器端返回注册结果
        response_data = command_socket.recv(4096).decode('utf-8')
        response = json.loads(response_data)
        if response["signup_result"]:
            print("[+] Account as been created successfully, please login.")
    else:
        print("[!] Username has already taken, please choose another one.")


def log_in(username: str, password: str):
    # 发送登录请求
    command_socket.sendall((json.dumps({"operation": "login", "username": username})).encode('utf-8'))
    print("[*] Login request sent to server")

    # 等待服务器端返回用户是否存在
    response_data = command_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)

    # 查看服务器端返回的消息
    if not response['username_checker']:
        print("[+] User not exist")
        return

    # 等待服务器端返回密语
    response_data = command_socket.recv(4096).decode('utf-8')
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
    command_socket.sendall((json.dumps({"decrypted_string": decrypted_string_str})).encode('utf-8'))

    # 等待服务器返回登陆状况
    response_data = command_socket.recv(4096).decode('utf-8')
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


def mkdir(dir_name: str):
    global current_dir, running, login_statue
    print(f"CURRENT DIR: {current_dir}")
    # 发送创建文件夹请求
    print("[*] Sending mkdir request to server")
    command_socket.sendall((json.dumps({"operation": "mkdir", "username": global_username})).encode('utf-8'))

    # 等待服务器端检查用户是否为登陆状态
    response_data = command_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)
    if response["user_available_check"]:
        print("[+] User availability check passed, continue")
    else:
        print("[!] User login timeout, please relog in")
        running = False
        login_statue = False

    # 将所需信息发送给服务器端
    command_socket.sendall((json.dumps({"operation": "mkdir",
                                        "username": global_username,
                                        "current_dir": current_dir,
                                        "new_dir_name": dir_name})).encode('utf-8'))

    # 接收服务器返回的消息
    response_data = command_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)
    if response['mkdir_result']:
        print(response['message'])
    else:
        print(response['message'])


def ls():
    global current_dir, running, login_statue

    # 发送ls命令请求
    print("[*] Sending ls request to server")
    command_socket.sendall((json.dumps({"operation": "ls", "username": global_username})).encode('utf-8'))

    # 等待服务器端检查用户是否为登陆状态
    response_data = command_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)
    if response["user_available_check"]:
        print("[+] User availability check passed, continue")
    else:
        print("[!] User login timeout, please relog in")
        running = False
        login_statue = False

    # 将所需信息发送给服务器端
    command_socket.sendall((json.dumps({"operation": "mkdir",
                                        "username": global_username,
                                        "current_dir": current_dir})).encode('utf-8'))

    # 等待接收服务器返回的消息
    response_data = command_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)
    if response["ls_result"]:
        print("\t\t\t\t".join(response["contents"]))
    else:
        print(response['message'])


def cd(target_dir: str):
    global current_dir, running, login_statue
    # 发送cd命令请求
    print("[*] Sending cd request to server")
    command_socket.sendall((json.dumps({"operation": "cd", "username": global_username})).encode('utf-8'))

    # 等待服务器端检查用户是否为登陆状态
    response_data = command_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)
    if response["user_available_check"]:
        print("[+] User availability check passed, continue")
    else:
        print("[!] User login timeout, please relog in")
        running = False
        login_statue = False

    # 将所需信息发送给服务器端
    command_socket.sendall((json.dumps({"operation": "cd",
                                        "username": global_username,
                                        "current_dir": current_dir,
                                        "target_dir": target_dir})).encode('utf-8'))

    # 等待接收服务器返回的消息并处理
    response_data = command_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)
    if response['cd_result']:
        print(f"[+] Successfully change direction to {target_dir}")
        current_dir += ("/" + target_dir)
    else:
        print(response['message'])


def back():
    global current_dir
    if current_dir == "":
        print("[*] You already at root")
    else:
        current_dir_list = current_dir.split('/')
        current_dir_list.pop()
        current_dir = '/'.join(current_dir_list)


def rm(target_dir: str):
    global current_dir, running, login_statue
    # 发送rm命令请求
    print("[*] Sending rm request to server")
    command_socket.sendall((json.dumps({
        "operation": "rm",
        "username": global_username})).encode('utf-8'))

    # 等待服务器端返回响应
    response_data = command_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)
    if response["user_available_check"]:
        print("[+] User availability check passed, continue")
    else:
        print("[!] User login timeout, please relog in")
        running = False
        login_statue = False

    # 将所需信息发送给服务器
    command_socket.sendall((json.dumps({
        "operation": "rm",
        "username": global_username,
        "current_dir": current_dir,
        "target_dir": target_dir})).encode('utf-8'))

    # 等待接收服务器返回的消息并处理
    response_data = command_socket.recv(4096).decode('utf-8')
    response = json.loads(response_data)
    if 'rm_result' in response:
        if response['rm_result']:
            print(response['message'])
        else:
            print(response['message'])
    else:
        print("[!] Unexpected response from server")


def root():
    global current_dir
    current_dir = ""


def start_client():
    global current_dir
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
            command = input(current_dir)
            command = command.split(" ")
            if command[0] == "upload":
                continue
            elif command[0] == "download":
                continue
            elif command[0] == "ls":
                continue
            elif command[0] == "mkdir":
                continue
            elif command[0] == "back":
                continue
            elif command[0] == "help":
                continue
            elif command[0] == "mkdir":
                mkdir(command[1])
            elif command[0] == "cd":
                continue
            else:
                print("Wrong command use help to see full commands")


# start_client()
# sign_up("test", "123456")
log_in("test", "123456")
current_dir = ""
ls()
rm("rm_root_test")
ls()
print(f"CURRENT DIR:{current_dir}")

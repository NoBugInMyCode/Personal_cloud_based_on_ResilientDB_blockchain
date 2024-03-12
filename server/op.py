import json
import socket
import random
import string
import Crypto
import sys
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import binascii
import hashlib
from pymongo import MongoClient

sys.path.append("kv-service_python_api")
from kv_operation import get_value, set_value

# 连接到MongoDB实例
client = MongoClient('mongodb://localhost:27017/')


def _string_to_public_key(pub_key_string):
    """Convert a string to an RSA public key"""
    return RSA.importKey(pub_key_string.encode('utf-8'))


def _hash_with_sha256(input_string):
    """Hash a string with SHA256"""
    sha_signature = hashlib.sha256(input_string.encode()).hexdigest()
    return sha_signature


def username_checker(user_name: str):
    checker = get_value(user_name)
    if checker == "\n" or checker == " " or checker == "":
        return True
    else:
        return False


def sign_up(pub_key_str: str, user_name: str) -> bool:
    set_value(user_name, pub_key_str)
    db = client[user_name]
    collection = db['metadata']
    collection.insert_one({"public key": pub_key_str})
    set_value(user_name + " file_structure", json.dumps({"~/": {}}))
    return True


def cd(user_name: str, current_dir: str, target_dir_name: str, client_socket: socket.socket):
    # 加载当前用户的文件结构
    file_structure = json.loads(get_value(user_name + " file_structure"))

    # 准备检查的目标目录，考虑到根目录的特殊情况
    if current_dir == "~/" and target_dir_name == "":
        # 已经在根目录，无需更改
        return current_dir

    # 处理当前目录和目标目录的路径格式
    current_dir = current_dir.rstrip("/") + "/"  # 确保以"/"结尾
    target_dir_path = current_dir + target_dir_name  # 构造完整目标目录路径

    current_dir_parts = current_dir.strip("/").split('/')
    target_dir_parts = target_dir_path.strip("/").split('/')

    # 尝试定位到目标目录
    target_dir = file_structure.get("~/", {})
    for part in target_dir_parts:
        part = "/" + part  # 确保格式一致
        if part in target_dir:
            target_dir = target_dir[part]
        else:
            # 目标目录不存在，发送错误消息
            client_socket.sendall(
                json.dumps({"cd_result": False, "message": "[!] Directory not found"}).encode('utf-8'))
            return current_dir  # 返回原来的目录路径，不更改

    # 目标目录存在，发送成功消息
    new_current_dir = "/".join(target_dir_parts)
    client_socket.sendall(json.dumps({"cd_result": True, "new_dir": new_current_dir}).encode('utf-8'))
    return new_current_dir


def mkdir(user_name: str, current_dir: str, new_dir_name: str, client_socket):
    # TESTED
    file_structure = json.loads(get_value(user_name + " file_structure"))
    # print(f"FILE STRUCTURE: {file_structure}")
    # print(f"CURRENT DIR:{current_dir}")
    current_dir_parts = current_dir.strip("/").split('/')
    if current_dir_parts[-1] == "":
        current_dir_parts.remove("")
    # 从根目录开始寻找目标目录
    target_dir = file_structure["~/"]
    # print(f"TARGET DIR:{(target_dir)}")
    # 遍历当前目录路径中的每一部分以找到目标目录
    for sub_dir in current_dir_parts:
        # print(f"SUB DIR:{sub_dir}")
        sub_dir = "/" + sub_dir
        if sub_dir in target_dir:
            target_dir = target_dir[sub_dir]
        else:
            # 如果当前路径部分不存在，则发送错误消息给客户端并返回
            client_socket.sendall(
                json.dumps({"mkdir_result": False, "message": f"[!] Directory not found"}).encode('utf-8'))
            return

    # 检查新目录是否已存在
    if new_dir_name in target_dir:
        client_socket.sendall(
            json.dumps({"mkdir_result": False, "message": f"[!] Directory already exists"}).encode('utf-8'))
        return
    else:
        # 创建新目录
        target_dir[new_dir_name] = {}
        # print(f"MODIFIED FILE STRUCTURE: {file_structure}")
        # 将更新后的文件结构保存回数据库
        # print(f"MODIFIED FILE STRUCTURE: {file_structure}")
        set_value(user_name + " file_structure", json.dumps(file_structure))

        # 发送成功消息
        client_socket.sendall(
            json.dumps({"mkdir_result": True, "message": f"[+] {new_dir_name} created successfully"}).encode('utf-8'))


def rm(user_name: str, current_dir: str, target_dir_name: str, client_socket: socket.socket):
    # TESTED
    file_structure = json.loads(get_value(user_name + " file_structure"))

    # 处理当前目录路径格式
    current_dir = current_dir.rstrip("/") + "/"  # 确保以"/"结尾
    target_dir_path = current_dir + target_dir_name  # 构造完整目标目录路径

    current_dir_parts = current_dir.strip("/").split('/')
    target_dir_parts = target_dir_path.strip("/").split('/')

    # 尝试定位到目标目录的父目录
    parent_dir = file_structure.get("~/", {})
    for part in target_dir_parts[:-1]:  # 排除目标目录名，找到其父目录
        part = "/" + part  # 确保格式一致
        if part in parent_dir:
            parent_dir = parent_dir[part]
        else:
            # 目标目录的父目录不存在，发送错误消息
            client_socket.sendall(
                json.dumps({"rm_result": False, "message": "[!] Parent directory not found"}).encode('utf-8'))
            return

    # 检查目标目录是否存在
    target_dir_name = "/" + target_dir_name  # 确保格式一致
    if target_dir_name in parent_dir:
        # 检查目标目录是否为空
        if not parent_dir[target_dir_name]:  # 如果目标目录为空
            del parent_dir[target_dir_name]  # 删除目标目录
            set_value(user_name + " file_structure", json.dumps(file_structure))  # 更新数据库中的文件结构
            client_socket.sendall(json.dumps(
                {"rm_result": True, "message": f"[+] Directory {target_dir_name} removed successfully"}).encode(
                'utf-8'))
        else:
            client_socket.sendall(
                json.dumps({"rm_result": False, "message": "[!] Directory is not empty"}).encode('utf-8'))
    else:
        client_socket.sendall(json.dumps({"rm_result": False, "message": "[!] Directory not found"}).encode('utf-8'))


def ls(current_dir: str, user_name: str, client_socket: socket.socket):
    # TESTED
    file_structure = json.loads(get_value(user_name + " file_structure"))

    # 从根目录开始寻找目标目录
    target_dir = file_structure["~/"]
    current_dir_parts = current_dir.strip("/").split('/')

    # 如果current_dir_parts为空，说明当前目录是根目录，不需要进一步解析
    if not current_dir_parts or current_dir_parts == ['']:
        dir_contents = list(target_dir.keys())
        client_socket.sendall(json.dumps({"ls_result": True, "contents": dir_contents}).encode('utf-8'))
        return

    # 遍历当前目录路径中的每一部分以找到目标目录
    for sub_dir in current_dir_parts:
        sub_dir = "/" + sub_dir
        if sub_dir:  # 忽略空的sub_dir部分
            if sub_dir in target_dir:
                target_dir = target_dir[sub_dir]
            else:
                # 如果当前路径部分不存在，则发送错误消息给客户端并返回
                client_socket.sendall(
                    json.dumps({"ls_result": False, "message": "[!] Directory not found"}).encode('utf-8'))
                return

    # 列出目标目录下的所有文件和目录
    dir_contents = list(target_dir.keys())

    # 发送目录内容给客户端
    client_socket.sendall(json.dumps({"ls_result": True, "contents": dir_contents}).encode('utf-8'))


def login(user_name: str, client_socket: socket.socket):
    # TESTED
    pub_key_string = get_value(user_name)
    if pub_key_string == "" or pub_key_string == "\n" or pub_key_string == " ":
        print("[!] User name check not pass login refuse")
        client_socket.sendall((json.dumps({"username_checker": False})).encode('utf-8'))
    else:
        print("[+] User name check passed continue login process")
        pub_key = _string_to_public_key(pub_key_string)
        client_socket.sendall((json.dumps({"username_checker": True})).encode('utf-8'))

        # Create a random string of length 20
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
        print("[+] Generating random string")

        # Encrypt random string
        print("[+] Encrypting random string with user's RSA public key")
        cipher_rsa = PKCS1_OAEP.new(pub_key)
        encrypted_random_string = cipher_rsa.encrypt(random_string.encode())
        encrypted_random_string = binascii.hexlify(encrypted_random_string).decode('ascii')

        # Send encrypted string to client
        print("[+] Sending encrypted string to user")
        client_socket.sendall((json.dumps({"encrypted_string": encrypted_random_string})).encode('utf-8'))

        # Wait client to response
        response_data = client_socket.recv(4096).decode('utf-8')
        response = json.loads(response_data)

        # Check if match
        print("[+] Get decrypted string from client, checking...")
        decrypted_string = response["decrypted_string"]
        if decrypted_string == random_string:
            print(f"[+] Check passed {user_name} logged in")
            client_socket.sendall((json.dumps({"login_result": True})).encode('utf-8'))
            return True
        else:
            print(f"[!] Check not passed log in refused")
            client_socket.sendall((json.dumps({"login_result": False})).encode('utf-8'))
            return False

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
    return True


def login(user_name: str, client_socket: socket.socket):
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

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


def _hash_with_sha256(input_string):
    """Hash a string with SHA256"""
    sha_signature = hashlib.sha256(input_string.encode()).hexdigest()
    return sha_signature


def sign_up(user_name: str, enc_psw: str):
    checker = get_value(user_name)
    if checker == "\n" or checker == " " or checker == "":
        set_value(user_name, enc_psw)
        db = client[user_name]
        return True
    else:
        return False

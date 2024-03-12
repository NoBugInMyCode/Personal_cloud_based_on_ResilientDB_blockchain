import binascii
import os
import random
import string
import sys

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

sys.path.append("kv-service_python_api/")
from kv_operation import get_value, set_value

# print(set_value("test", "\n"))
# print(get_value("test"))

pub_key = RSA.importKey(get_value("test").encode('utf-8'))

random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
cipher_rsa = PKCS1_OAEP.new(pub_key)
encrypted_random_string = cipher_rsa.encrypt(random_string.encode())
encrypted_random_string = binascii.hexlify(encrypted_random_string).decode('ascii')






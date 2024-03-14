import binascii
import os
import random
import string
import sys
import json
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

sys.path.append("kv-service_python_api/")
from kv_operation import get_value, set_value

data = {
    "~/": {
        "test_img.jpeg": {"_id": 123, "Upload_date": 2024, "file_size": 3},
        "/picture": {
            "/my_picture": {"/test_rm": {}},
            "/children_picture": {},
            "/friend_picture": {},
            "/parent_picture": {},
        },
        "/document": {
            "/personal_document": {},
            "/work_document": {},
        },
        "/rm_root_test": {},
    }
}
# current_dir = "~/picture"
# # set_value("test", "\n")
# set_value("test file_structure", json.dumps(data))
print(get_value("test file_structure"))
# print(get_value("test"))


# a = (json.dumps({"operation": "mkdir", "username": "aaa"})).encode('utf-8')
# print(type(a))


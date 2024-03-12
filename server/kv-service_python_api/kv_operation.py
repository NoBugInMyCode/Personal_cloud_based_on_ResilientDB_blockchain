import sys
import os

current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
parent_dir = os.path.dirname(current_dir)
new_path_dir = os.path.join(parent_dir, "kv-service_python_api", "bazel-out", "k8-fastbuild", "bin")
sys.path.insert(0, new_path_dir)
import pybind_kv

config_path = current_dir + "/kv_server.config"

def set_value(key: str, value: str):
    pybind_kv.set(key, value, config_path)


def get_value(key: str) -> str:
    return pybind_kv.get(key, config_path)

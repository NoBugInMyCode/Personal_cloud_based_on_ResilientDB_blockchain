import os
import sys
sys.path.append("kv-service_python_api/")
from kv_operation import get_value, set_value

print(set_value("test", "\n"))
print(get_value("test"))




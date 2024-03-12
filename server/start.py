import socket
import threading
import json
import time
from op import username_checker, sign_up, login

user_list = {}


def remove_inactive_users():
    global user_list
    """移除超过30秒未活动的用户"""
    while True:
        current_time = time.time()
        inactive_users = [user for user, last_activity in user_list.items() if current_time - last_activity > 60]
        for user in inactive_users:
            del user_list[user]
        time.sleep(2)  # 每2秒检查一次


def handle_client_connection(client_socket):
    try:
        while True:
            try:
                # 接收客户端发送的数据
                received_data = client_socket.recv(4096).decode()
                if not received_data:
                    break  # 如果客户端关闭连接，则退出循环

                # 将接收到的JSON字符串转换回Python对象
                data = json.loads(received_data)
                print(f"[+] Received data: {data}")
                op = data.get("operation")

                if op == "signup":
                    user_name = data["username"]
                    if username_checker(user_name):
                        client_socket.sendall((json.dumps({"checker_result": True})).encode('utf-8'))
                    else:
                        client_socket.sendall((json.dumps({"checker_result": False})).encode('utf-8'))
                        break

                    # 等待客户端返回公钥
                    response_data = client_socket.recv(4096).decode('utf-8')
                    print(f"[+] Received public key from client")
                    response = json.loads(response_data)
                    pub_key_str = response["pub_key_str"]

                    # Set up user
                    sign_up(pub_key_str, user_name)

                    # Send success message back
                    client_socket.sendall((json.dumps({"signup_result": True})).encode('utf-8'))

                elif op == "login":
                    username = data['username']
                    login_result = login(username, client_socket)
                    if login_result:
                        global user_list
                        user_list[username] = time.time()
            except ConnectionResetError:
                print("Connection reset by peer")
                client_socket.close()
                break  # 退出循环，结束线程
            except json.JSONDecodeError:
                print("Received non-JSON data")
                client_socket.close()
                # 可以选择断开连接或忽略错误
                break
            except Exception as e:
                print(f"Unexpected error: {e}")
                client_socket.close()
                break  # 遇到其他异常，退出循环

    finally:
        client_socket.close()  # 确保释放资源


def handle_extend_connection(client_socket):
    global user_list
    received_data = client_socket.recv(4096).decode()
    if "username" in received_data:
        username = received_data["username"]
        if username in user_list:
            user_list[username] = time.time()


def start_server(server_ip, command_port, extend_port):
    # 创建原有的命令socket
    command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    command_socket.bind((server_ip, command_port))
    command_socket.listen(5)
    print(f"[*] Listening on {server_ip}:{command_port} for operations")

    # 创建新的extend socket
    extend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    extend_socket.bind((server_ip, extend_port))
    extend_socket.listen(5)
    print(f"[*] Listening on {server_ip}:{extend_port} for extend requests")

    def accept_connections(sock, handler):
        while True:
            client_sock, address = sock.accept()
            print(f"[+] {address} is connected.")
            thread = threading.Thread(target=handler, args=(client_sock,))
            thread.start()

    # 启动监听循环
    command_thread = threading.Thread(target=accept_connections, args=(command_socket, handle_client_connection))
    command_thread.start()

    extend_thread = threading.Thread(target=accept_connections, args=(extend_socket, handle_extend_connection))
    extend_thread.start()

    # 启用用户超时检查循环
    user_timing_thread = threading.Thread(target=remove_inactive_users)
    user_timing_thread.start()


# 启动服务器
start_server('10.0.0.110', 5001, 5002)

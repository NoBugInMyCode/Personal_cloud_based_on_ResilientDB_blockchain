import socket
import threading
import json
import time
from op import username_checker, sign_up

user_list = {}


def remove_inactive_users():
    """移除超过30秒未活动的用户"""
    global user_list
    while True:
        current_time = time.time()
        inactive_users = [user for user, last_activity in user_list.items() if current_time - last_activity > 60]
        for user in inactive_users:
            del user_list[user]
        time.sleep(2)  # 每2秒检查一次


def handle_client_connection(client_socket):
    try:
        while True:
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

    finally:
        client_socket.close()  # 确保释放资源


def start_server(server_ip, server_port):
    # 创建socket对象
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 绑定IP地址和端口号
    server_socket.bind((server_ip, server_port))
    # 监听连接
    server_socket.listen(5)
    print(f"[*] Listening as {server_ip}:{server_port}")

    try:
        while True:
            # 接受客户端连接
            client_socket, address = server_socket.accept()
            print(f"[+] {address} is connected.")

            # 为每个客户端创建一个新的线程并启动
            client_thread = threading.Thread(target=handle_client_connection, args=(client_socket,))
            client_thread.start()

            # 监控线程，用来监控每个用户的连接时间，如果超过60秒没有操作则移除
            monitor_thread = threading.Thread(target=remove_inactive_users)
            monitor_thread.start()

    finally:
        server_socket.close()  # 确保释放资源


# 启动服务器
start_server('10.0.0.110', 5001)

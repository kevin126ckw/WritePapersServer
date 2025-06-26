#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2025/6/2
# @File    : net.py
# @Software: PyCharm
# @Desc    :
# @Author  : Kevin Chang
import threading
import traceback
# import paperlib as lib
import json
import sys
import time
# import database
import networking
import structlog

logger = structlog.get_logger()
net = networking.ServerNetwork()

server_listen_thread = None
logged_in_clients = {}

class Server:
    @staticmethod
    def handle_client(conn, addr):
        """
        客户端处理函数，这个函数将在一个单独的线程中服务客户端
        Args:
            :param conn: 客户端连接
            :param addr: 客户端地址
        Returns:
            :return: None
        """
        global server_listen_thread
        username = None
        raw_msg = None
        logger.info(f"New client connected: {addr}")
        net.send_packet(conn, "server_hello", {"content": "Hello, world!"})
        buffer = ""
        try:
            # 主消息处理循环
            while True:
                try:
                    # 接收并解析客户端消息
                    data = conn.recv(1024).decode('utf-8')
                    if not data:
                        logger.info(f"Client {addr} disconnected.")
                        break
                    buffer += data



                    try:
                        # 此时已经得到一个完整的数据包
                        # 尝试解析数据包
                        message = json.loads(data)
                        # 此时已经获得了可使用的数据
                        if message["token"]:
                            token = message["token"]
                            str(token)  # 还是强忽略IDE的警告(好神经啊)
                            # 处理登录请求
                            if message['type'] == "login":  # 暂时不验证
                                username = message['payload']['username']
                                password = message['payload']['password']
                                if username and password:
                                    net.send_packet(conn, "login_result", {"success": True})
                                    # 添加到已登录用户列表
                                    logged_in_clients[username] = conn
                                else:
                                    net.send_packet(conn, "login_result", {"success": False})
                                    # 登录失败就残酷的直接断开连接
                                    net.remove_client(conn)
                            elif message['type'] == "send_message":
                                if username is not None:
                                    to_user = message['payload']['to_user']
                                    message = message['payload']['message']
                                    if to_user and message:
                                        net.send_packet(conn, "send_message_result", {"success": True})
                                        # 转发消息
                                        # 此时to_user为接收方的用户名，需修改
                                        net.send_packet(logged_in_clients[to_user], "new_message", {"from_user": username, "message": message})
                                    else:
                                        net.send_packet(conn, "send_message_result", {"success": False})
                    except json.JSONDecodeError as e:
                        logger.error(f"JSON解析失败: {e}, 数据内容: {raw_msg}")
                        traceback.print_exc()
                except Exception as e:
                    # 处理错误
                    logger.error(f"Error processing client: {e}")
                    traceback.print_exc()
        finally:
            # 连接关闭处理
            # 确保移除客户端连接
            if conn in net.clients:
                net.remove_client(conn)
def main():
    global net,server_listen_thread
    try:
        logger.info("Starting net...")
        server = Server()
        server_listen_thread = threading.Thread(target=net.listen_clients, args=(server.handle_client,), daemon=True)
        server_listen_thread.start()
        while True:
            # 循环检查当前连接
            time.sleep(3)
            logger.debug("Current Clients conn :" + str(net.clients))
    except KeyboardInterrupt:
        # 键盘中断处理
        logger.info("Server stopped.")
        for client in net.clients:
            client.close()
        sys.exit(0)


if __name__ == "__main__":
    main()

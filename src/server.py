#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2025/6/2
# @File    : net.py
# @Software: PyCharm
# @Desc    :
# @Author  : Kevin Chang
import base64
import threading
import traceback
import paperlib as lib
import json
import sys
import time
import database
import networking
import structlog
import socket
import color
from colorama import init
# from not_important_codes import afk

init(autoreset=True)
logger = structlog.get_logger()
net = networking.ServerNetwork()
color = color.Colored()

server_listen_thread = NotImplemented
# afk_thread = threading.Thread(target=afk, args=(net,), daemon=True)
# need_afk = False
logged_in_clients = {}

server = NotImplemented

class Server:
    def __init__(self):
        self.db = database.Database()
        self.db.connect(lib.read_xml("database/file"))
    @staticmethod
    def handle_egg(conn, addr):
        data_byte = b'GET ' + conn.recv(1024)
        data = data_byte.decode('utf-8')
        if data.startswith("GET /favicon.ico"):
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n')
            net.remove_client(conn)
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Hello, World!</h1></body></html>')
        logger.info(f"Egg request from {addr}")
        net.remove_client(conn)

    def handle_client(self, conn, addr):
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
        uid = None
        raw_msg = None
        logger.info(f"New client connected: {addr}")
        # R.I.P Hello, world while connecting.
        # Remember him and don't remove him.
        # net.send_packet(conn, "server_hello", {"content": "Hello, world!"})
        try:
            # 主消息处理循环
            while True:
                try:
                    # 首先接收4字节的数据长度
                    length_bytes = conn.recv(4)
                    if length_bytes == b'GET ':
                        self.handle_egg(conn, addr)
                        # net.remove_client(conn)
                        # break
                    if not length_bytes:
                        logger.info(f"Client {addr} disconnected.")
                        # net.remove_client(conn)
                        break
                    # 解析数据长度
                    data_length = int.from_bytes(length_bytes, byteorder='big')
                    # 根据长度接收完整数据
                    data = b''
                    while len(data) < data_length:
                        remaining = data_length - len(data)
                        chunk = conn.recv(min(1024, remaining))
                        if not chunk:
                            logger.info(f"Client {addr} disconnected during data transfer.")
                            break
                        data += chunk
                    if len(data) == data_length:
                        # 解析数据包
                        message = json.loads(data.decode('utf-8'))
                        logger.debug(f"Received message from {addr}: {message}")

                        # 此时已经获得了可使用的数据
                        if message["token"]:
                            token = message["token"]
                            str(token)  # 还是强忽略IDE的警告(好神经啊)

                            # 处理登录请求
                            match message['type']:
                                case "login":  # 把验证加回来了
                                    username = message['payload']['username']
                                    password = message['payload']['password']
                                    uid = str(self.db.get_uid_by_username(username))
                                    if self.db.check_account_password(username, password) and uid not in net.logged_in_clients:
                                        net.send_packet(conn, "login_result", {"success": True, "uid": uid})# 发送登录结果（带UID）
                                        net.send_packet(conn, "welcome_back", {"message": f"Welcome back, {self.db.get_name_by_uid(uid)}!"})

                                        # 添加到已登录用户列表
                                        net.logged_in_clients[uid] = conn
                                    else:
                                        net.send_packet(conn, "login_result", {"success": False})
                                        # 登录失败就残酷的直接断开连接
                                        net.remove_client(conn)
                                        break
                                case "send_message":
                                    if username is not None:
                                        to_user = message['payload']['to_user']
                                        message_type = message['payload']['type']
                                        message = message['payload']['message']
                                        send_time = time.time()
                                        if message_type == "text":
                                            if to_user and message:
                                                # net.send_packet(conn, "send_message_result", {"success": True})
                                                # 转发消息
                                                if to_user in net.logged_in_clients:
                                                    net.send_packet(net.logged_in_clients[to_user], "new_message",
                                                                {"from_user": uid, "message": message, "time": send_time, "type": "text"})
                                                else:
                                                    # 添加到数据库
                                                    logger.debug("Adding chat history to database.")
                                                    self.db.save_chat_history(message, uid, to_user, "text")
                                            else:
                                                net.send_packet(conn, "send_message_result", {"success": False})
                                        elif message_type == "image":
                                            if to_user and message:
                                                message = base64.b64decode(message)
                                                # 转发图片消息
                                                if to_user in net.logged_in_clients:
                                                    net.send_packet(net.logged_in_clients[to_user], "new_message",
                                                                {"from_user": uid, "message": base64.b64decode(message), "time": send_time, "type": "image"})
                                                else:
                                                    # 添加消息到数据库
                                                    logger.debug("Adding chat history to database.")
                                                    self.db.save_chat_history(message, uid, to_user, "image")
                                        else:
                                            net.send_packet(conn, "send_message_result", {"success": False})
                                case "get_offline_messages":
                                    # 离线消息
                                    net.send_packet(conn, "offline_messages", self.db.select_sql("offline_chat_history",
                                                                                                 'content, from_user, to_user, send_time',
                                                                                                 f"to_user={uid}"))
                                    self.db.delete_chat_history_from_db(uid)
                                case "register_account":
                                    username = message['payload']['username']
                                    password = message['payload']['password']
                                    if self.db.check_account_exists(username):
                                        net.send_packet(conn, "register_result", {"success": False})
                                        continue
                                    result = self.db.add_account(username, password, username, time.time())
                                    if result[0][0]:
                                        net.send_packet(conn, "register_result",
                                                        {"success": True, 'uid': result[0][0], 'username': username,
                                                         'password': password})
                                    else:
                                        net.send_packet(conn, "register_result", {"success": False})
                                case "add_friend":
                                    if message['payload']['friend_id_type'] == "username":
                                        # 根据用户名加好友的处理
                                        friend_token = self.db.select_sql("user", "friend_token",
                                                                          f"username={message['payload']['friend_id']}")[0][
                                            0]
                                        if friend_token == message['payload']['verify_token']:
                                            # 验证口令正确
                                            net.send_packet(conn, "add_friend_result", {"success": True,
                                                                                       "friend_uid": self.db.get_uid_by_username(
                                                                                           message['payload']['friend_id']),
                                                                                       "friend_username": self.db.get_uid_by_username(
                                                                                           message['payload']['friend_id']),
                                                                                       "friend_name": self.db.get_name_by_uid(
                                                                                           message['payload'][
                                                                                               'friend_id'])})
                                            if uid in net.logged_in_clients:
                                                # 请求方在线
                                                net.send_packet(conn, "new_message", {
                                                    "from_user": self.db.get_uid_by_username(
                                                        message['payload']['friend_id']),
                                                    "message": "我通过了你的好友验证请求，现在我们可以开始聊天了",
                                                    "time": time.time(), "need_update_contact": False})
                                            else:
                                                # 请求方不在线
                                                # 添加到数据库
                                                logger.debug("Adding chat history to database.")
                                                self.db.save_chat_history("我通过了你的好友验证请求，现在我们可以开始聊天了",
                                                                          self.db.get_uid_by_username(
                                                                              message['payload']['friend_id']), uid)
                                            if self.db.get_uid_by_username(
                                                    message['payload']['friend_id']) in net.logged_in_clients:
                                                # 响应方在线
                                                net.send_packet(net.logged_in_clients[self.db.get_uid_by_username(
                                                    message['payload']['friend_id'])], "new_message", {"from_user": uid,
                                                                                                       "message": "你通过了我的好友验证请求，现在我们可以开始聊天了",
                                                                                                       "time": time.time(),
                                                                                                       "need_update_contact": False})

                                            else:
                                                # 响应方不在线
                                                self.db.save_chat_history("你通过了我的好友验证请求，现在我们可以开始聊天了",
                                                                          uid, self.db.get_uid_by_username(
                                                        message['payload']['friend_id']))
                                    elif message['payload']['friend_id_type'] == "uid":
                                        # 根据uid加好友的处理
                                        friend_id = message['payload']['friend_id']
                                        # 判空保护
                                        res = self.db.select_sql("user", "friend_token", f"id={friend_id}")
                                        if not res:
                                            net.send_packet(conn, "add_friend_result", {"success": False, "reason": "friend_not_found"})
                                            continue

                                        friend_token = res[0][0]

                                        if friend_token == message['payload']['verify_token']:
                                            # 验证口令正确
                                            if str(message['payload']['friend_id']) in net.logged_in_clients:
                                                # 响应方在线
                                                net.send_packet(net.logged_in_clients[str(message['payload']['friend_id'])],
                                                                "add_friend_result",
                                                                {"success": True, "friend_uid": uid,
                                                                 "friend_username": self.db.get_username_by_uid(
                                                                     uid),
                                                                 "friend_name": self.db.get_name_by_uid(
                                                                     uid)}
                                                                )
                                                net.send_packet(net.logged_in_clients[
                                                    str(message['payload']['friend_id'])], "new_message", {"from_user": uid,
                                                                                                       "message": "你通过了我的好友验证请求，现在我们可以开始聊天了",
                                                                                                       "time": time.time(),
                                                                                                       "need_update_contact": False})
                                            else:
                                                # 响应方不在线
                                                net.send_packet(conn, "add_friend_result", {"success": False, "reason": "friend_not_online"})
                                                continue
                                            net.send_packet(conn, "add_friend_result",
                                                            {"success": True, "friend_uid": message['payload']['friend_id'],
                                                             "friend_username": self.db.get_username_by_uid(
                                                                 message['payload']['friend_id']),
                                                             "friend_name": self.db.get_name_by_uid(
                                                                 message['payload']['friend_id'])})
                                            if str(uid) in net.logged_in_clients:
                                                # 请求方在线
                                                net.send_packet(conn, "new_message",
                                                                {"from_user": message['payload']['friend_id'],
                                                                 "message": "我通过了你的好友验证请求，现在我们可以开始聊天了",
                                                                 "time": time.time(), "need_update_contact": False})
                                            else:
                                                # 请求方不在线
                                                # 添加到数据库
                                                logger.debug("Adding chat history to database.")
                                                self.db.save_chat_history("我通过了你的好友验证请求，现在我们可以开始聊天了",
                                                                          message['payload']['friend_id'], uid)
                                        else:
                                            # 验证口令错误
                                            net.send_packet(conn, "add_friend_result", {"success": False, "reason": "verify_token_error"})
                                case "change_friend_token":
                                    self.db.change_friend_token(uid, message['payload']['new_friend_token'])
                                case "get_friend_token":
                                    res = self.db.select_sql("user", "friend_token", f"id={uid}")
                                    if not res:
                                        net.send_packet(conn, "friend_token_result", {"friend_token": None})
                                        continue

                                    friend_token = res[0][0]
                                    net.send_packet(conn, "friend_token_result", {"friend_token": friend_token})
                                case _:
                                    logger.warning(f"Unknown packet type: {message['type']}")
                except ConnectionResetError:
                    logger.info(f"Client {addr} forcibly disconnected.")
                    if conn in net.clients:
                        if str(uid) in net.logged_in_clients:
                            logger.debug(f"Client {conn} logged out")
                            del net.logged_in_clients[str(uid)]
                        net.remove_client(conn)
                    break
                except OSError:
                    break
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
                if str(uid) in net.logged_in_clients:
                    logger.debug(f"Client {conn} logged out")
                    del net.logged_in_clients[str(uid)]
                net.remove_client(conn)

def stop_server():
    logger.info("Stopping server...")
    for client in net.clients:
        client.close()
    if net.sock:
        net.sock.shutdown(socket.SHUT_RDWR)
        net.sock.close()
        pass
    server.db.close()
    logger.info("Server stopped.")
    sys.exit(0)

r"""
                    _ooOoo_
                   o8888888o
                   88" . "88
                   (| -_- |)
                    O\ = /O
                ____/`---'\____
              .   ' \\| |// `.
               / \\||| : |||// \
             / _||||| -:- |||||- \
               | | \\\ - /// | |
             | \_| ''\---/'' | |
              \ .-\__ `-` ___/-. /
           ___`. .' /--.--\ `. . __
        ."" '< `.___\_<|>_/___.' >'"".
       | | : `- \`.;`\ _ /`;.`/ - ` : | |
         \ \ `-. \_ __\ /__ _/ .-` / /
 ======`-.____`-.___\_____/___.-`____.-'======
                    `=---='

 .............................................
          佛祖保佑             永无BUG
  佛曰:
          写字楼里写字间，写字间里程序员；
          程序人员写程序，又拿程序换酒钱。
          酒醒只在网上坐，酒醉还来网下眠；
          酒醉酒醒日复日，网上网下年复年。
          但愿老死电脑间，不愿鞠躬老板前；
          奔驰宝马贵者趣，公交自行程序员。
          别人笑我忒疯癫，我笑自己命太贱；
          不见满街漂亮妹，哪个归得程序员？

"""


def main():
    global net, server_listen_thread, server
    try:
        server_ascii = r"""
         _    _      _ _      ______                                                          
        | |  | |    (_) |     | ___ \                                                         
        | |  | |_ __ _| |_ ___| |_/ /_ _ _ __   ___ _ __ ___     ___  ___ _ ____   _____ _ __ 
        | |/\| | '__| | __/ _ \  __/ _` | '_ \ / _ \ '__/ __|   / __|/ _ \ '__\ \ / / _ \ '__|
        \  /\  / |  | | ||  __/ | | (_| | |_) |  __/ |  \__ \   \__ \  __/ |   \ V /  __/ |   
         \/  \/|_|  |_|\__\___\_|  \__,_| .__/ \___|_|  |___/   |___/\___|_|    \_/ \___|_|   
                                        | |                                                   
                                        |_|                                                   
                                                                    v1.0.0 development
        """
        print(color.green(server_ascii))
        logger.info("Starting server...")
        server = Server()
        server_listen_thread = threading.Thread(target=net.listen_clients, args=(server.handle_client,), daemon=True)
        server_listen_thread.start()
        while True:
            # 服务器控制台
            """
            time.sleep(3)
            logger.debug("Current Clients conn :" + str(net.clients))
            logger.debug("Current Logged In Clients :" + str(net.logged_in_clients))
            """
            time.sleep(0.03)
            command = input(color.green("Write papers server >>> "))
            if command.startswith("stop"):
                stop_server()
            elif command.startswith("status"):
                logger.info("Server status:")
                logger.info("Current Clients conn :" + str(net.clients))
                logger.info("Current Logged In Clients :" + str(net.logged_in_clients))
            elif command.startswith("help"):
                logger.info("Available commands:")
                logger.info("stop - Stop the server")
                logger.info("status - Show the status of the server")
                logger.info("check account exists - Check if an account exists")
                logger.info("help - Show this help message")
            elif command.startswith("check account exists"):
                logger.info(server.db.check_account_exists(command[21:]))
            elif command == "":
                pass
            else:
                logger.info("Invalid command.")
    except KeyboardInterrupt:
        # 键盘中断处理
        stop_server()


if __name__ == "__main__":
    main()

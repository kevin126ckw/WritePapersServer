#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2025/6/2
# @File    : server.py
# @Software: PyCharm
# @Desc    : WritePapers 聊天服务器
# @Author  : Kevin Chang

import base64
import json
import socket
import sys
import time
import threading
import traceback
import secrets
from typing import Dict, Optional, Tuple, Any

# 第三方库导入
import structlog
from colorama import init

# 本地模块导入
import paperlib as lib
import database
import networking
import color

# 初始化colorama，用于控制台彩色输出
init(autoreset=True)

# 全局变量初始化
logger = structlog.get_logger()  # 结构化日志记录器
net = networking.ServerNetwork()  # 网络管理器实例
color_helper = color.Colored()  # 控制台颜色工具

# 服务器状态相关变量
server_listen_thread = NotImplemented  # 服务器监听线程
logged_in_clients: Dict[str, socket.socket] = {}  # 已登录客户端字典: {uid: connection}
server_instance = NotImplemented  # 服务器实例


class Server:
    """
    聊天服务器主类
    负责处理客户端连接、用户认证、消息传递等核心功能
    """

    def __init__(self):
        """初始化服务器，建立数据库连接"""
        self.db = database.Database()
        self.db.connect(lib.read_xml("database/file"))
        logger.info("服务器实例初始化完成，数据库连接已建立")

    @staticmethod
    def handle_egg(conn: socket.socket, addr: Tuple[str, int]) -> None:
        """
        处理HTTP请求（彩蛋功能）
        当客户端发送HTTP GET请求时返回简单的HTML页面

        Args:
            :param conn: 客户端连接对象
            :param addr: 客户端地址信息
        """
        try:
            # 接收剩余的HTTP请求数据
            data_byte = b'GET ' + conn.recv(1024)
            data = data_byte.decode('utf-8')

            # 处理图标请求
            if data.startswith("GET /favicon.ico"):
                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n')
                net.remove_client(conn)
                return

            # 返回Hello World页面
            response = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Hello, World!</h1></body></html>'
            conn.sendall(response)
            logger.info(f"处理来自 {addr} 的HTTP请求")
            net.remove_client(conn)

        except Exception as e:
            logger.error(f"处理HTTP请求时出错: {e}")
            net.remove_client(conn)

    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        """
        客户端连接处理函数
        在独立线程中为每个客户端提供服务，处理登录、消息收发等操作

        Args:
            :param conn: 客户端连接对象
            :param addr: 客户端地址信息（IP, 端口）
        """
        # 客户端会话变量
        username: Optional[str] = None
        uid: Optional[str] = None
        raw_msg: Optional[str] = None
        token: str = secrets.token_urlsafe(32)  # 生成安全的会话令牌

        logger.info(f"客户端已连接: {addr}")

        try:
            # 主消息处理循环
            while True:
                try:
                    # 接收4字节的数据长度头
                    length_bytes = conn.recv(4)

                    # 检查是否为HTTP请求
                    if length_bytes == b'GET ':
                        self.handle_egg(conn, addr)
                        break

                    # 检查连接是否断开
                    if not length_bytes:
                        logger.info(f"客户端 {addr} 已断开连接")
                        break

                    # 解析数据包长度
                    data_length = int.from_bytes(length_bytes, byteorder='big')

                    # 接收完整的数据包
                    data = self._receive_complete_data(conn, data_length, addr)
                    if data is None:
                        break

                    # 解析JSON消息
                    try:
                        message = json.loads(data.decode('utf-8'))
                        logger.debug(f"收到来自 {addr} 的消息: {message}")
                    except json.JSONDecodeError as e:
                        logger.error(f"JSON解析失败: {e}")
                        continue

                    # 验证消息令牌
                    if not self._validate_token(message, token):
                        continue

                    # 处理登录请求
                    if message["token"] == "LOGIN" and message['type'] == "login":
                        login_result = self._handle_login(conn, message, token)
                        if login_result:
                            username, uid = login_result
                        else:
                            break  # 登录失败，断开连接
                        continue

                    # 处理已认证用户的其他请求
                    if not self._handle_authenticated_request(conn, message, uid):
                        break

                except ConnectionResetError:
                    logger.info(f"客户端 {addr} 强制断开连接")
                    self._cleanup_client_connection(conn, uid)
                    break
                except OSError:
                    break

        except json.JSONDecodeError as e:
            logger.error(f"JSON解析失败: {e}, 数据内容: {raw_msg}")
            traceback.print_exc()
        except Exception as e:
            logger.error(f"处理客户端时出错: {e}")
            traceback.print_exc()
        finally:
            # 清理连接资源
            self._cleanup_client_connection(conn, uid)

    @staticmethod
    def _receive_complete_data(conn: socket.socket, data_length: int, addr: Tuple[str, int]) -> Optional[bytes]:
        """
        接收完整的数据包

        Args:
            :param conn: 客户端连接
            :param data_length: 期望接收的数据长度
            :param addr: 客户端地址

        Returns:
            :return str 接收到的完整数据，如果连接断开则返回None
        """
        data = b''
        while len(data) < data_length:
            remaining = data_length - len(data)
            try:
                chunk = conn.recv(min(1024, remaining))
                if not chunk:
                    logger.info(f"客户端 {addr} 在数据传输过程中断开连接")
                    return None
                data += chunk
            except (ConnectionResetError, OSError):
                logger.info(f"客户端 {addr} 连接异常断开")
                return None

        return data

    @staticmethod
    def _validate_token(message: Dict[str, Any], token: str) -> bool:
        """
        验证消息令牌

        Args:
            :param message: 收到的消息
            :param token: 会话令牌

        Returns:
            :return bool 令牌是否有效
        """
        msg_token = message.get("token")
        return msg_token == token or msg_token == "LOGIN"

    def _handle_login(self, conn: socket.socket, message: Dict[str, Any], token: str) -> Optional[Tuple[str, str]]:
        """
        处理用户登录请求

        Args:
            :param conn: 客户端连接
            :param message: 登录消息
            :param token: 会话令牌

        Returns:
            :return 登录成功返回(username, uid)，失败返回None
        """
        try:
            username = message['payload']['username']
            password = message['payload']['password']
            uid = str(self.db.get_uid_by_username(username))

            # 验证账号密码且确保用户未重复登录
            if self.db.check_account_password(username, password) and uid not in net.logged_in_clients:
                # 发送登录成功响应
                net.send_packet(conn, "login_result", {
                    "success": True,
                    "uid": uid,
                    "token": token
                })

                # 发送欢迎消息
                welcome_name = self.db.get_name_by_uid(uid)
                net.send_packet(conn, "welcome_back", {
                    "message": f"欢迎回来, {welcome_name}!"
                })

                # 将用户标记为已登录
                net.logged_in_clients[uid] = conn
                logger.info(f"用户 {username}({uid}) 登录成功")
                return username, uid
            else:
                # 登录失败处理
                net.send_packet(conn, "login_result", {"success": False})
                logger.warning(f"用户 {username} 登录失败")
                net.remove_client(conn)
                return None

        except KeyError as e:
            logger.error(f"登录请求格式错误: {e}")
            net.send_packet(conn, "login_result", {"success": False})
            net.remove_client(conn)
            return None

    def _handle_authenticated_request(self, conn: socket.socket, message: Dict[str, Any], uid: Optional[str]) -> bool:
        """
        处理已认证用户的请求

        Args:
            :param conn: 客户端连接
            :param message: 请求消息
            :param uid: 用户ID

        Returns:
            :return 是否继续保持连接
        """
        if uid is None:
            logger.warning("收到未认证用户的请求")
            return False

        message_type = message.get('type')

        try:
            # 根据消息类型分发处理
            match message_type:
                case "send_message":
                    return self._handle_send_message(conn, message, uid)
                case "get_offline_messages":
                    return self._handle_get_offline_messages(conn, uid)
                case "register_account":
                    return self._handle_register_account(conn, message)
                case "add_friend":
                    return self._handle_add_friend(conn, message, uid)
                case "change_friend_token":
                    return self._handle_change_friend_token(message, uid)
                case "get_friend_token":
                    return self._handle_get_friend_token(conn, uid)
                case _:
                    logger.warning(f"未知的消息类型: {message_type}")
                    return True

        except Exception as e:
            logger.error(f"处理请求时出错: {e}")
            traceback.print_exc()
            return True

    def _handle_send_message(self, conn: socket.socket, message: Dict[str, Any], uid: str) -> bool:
        """
        处理发送消息请求

        Args:
            :param conn: 客户端连接
            :param message: 消息内容
            :param uid: 发送者用户ID

        Returns:
            :return 是否继续保持连接
        """
        try:
            payload = message['payload']
            to_user = payload['to_user']
            message_type = payload['type']
            message_content = payload['message']
            send_time = time.time()

            if not to_user or not message_content:
                net.send_packet(conn, "send_message_result", {"success": False})
                return True

            # 处理文本消息
            if message_type == "text":
                return self._send_text_message(uid, to_user, message_content, send_time)

            # 处理图片消息
            elif message_type == "image":
                return self._send_image_message(uid, to_user, message_content, send_time)

            else:
                net.send_packet(conn, "send_message_result", {"success": False})
                return True

        except KeyError as e:
            logger.error(f"发送消息请求格式错误: {e}")
            return True

    def _send_text_message(self, from_uid: str, to_uid: str, content: str, send_time: float) -> bool:
        """
        发送文本消息

        Args:
            :param from_uid: 发送者ID
            :param to_uid: 接收者ID
            :param content: 消息内容
            :param send_time: 发送时间

        Returns:
            :return 是否成功处理
        """
        # 检查接收者是否在线
        if to_uid in net.logged_in_clients:
            # 在线用户直接转发
            net.send_packet(net.logged_in_clients[to_uid], "new_message", {
                "from_user": from_uid,
                "message": content,
                "time": send_time,
                "type": "text"
            })
            logger.debug(f"文本消息已转发给在线用户 {to_uid}")
        else:
            # 离线用户存储到数据库
            self.db.save_chat_history(content, from_uid, to_uid, "text")
            logger.debug(f"文本消息已保存到数据库，接收者: {to_uid}")

        return True

    def _send_image_message(self, from_uid: str, to_uid: str, content: str, send_time: float) -> bool:
        """
        发送图片消息

        Args:
            :param from_uid: 发送者ID
            :param to_uid: 接收者ID
            :param content: base64编码的图片内容
            :param send_time: 发送时间

        Returns:
            :return 是否成功处理
        """
        try:
            # 解码base64图片数据
            image_data = base64.b64decode(content)

            # 检查接收者是否在线
            if to_uid in net.logged_in_clients:
                # 在线用户直接转发
                net.send_packet(net.logged_in_clients[to_uid], "new_message", {
                    "from_user": from_uid,
                    "message": image_data,
                    "time": send_time,
                    "type": "image"
                })
                logger.debug(f"图片消息已转发给在线用户 {to_uid}")
            else:
                # 离线用户存储到数据库
                self.db.save_chat_history(image_data, from_uid, to_uid, "image")
                logger.debug(f"图片消息已保存到数据库，接收者: {to_uid}")

            return True

        except Exception as e:
            logger.error(f"处理图片消息时出错: {e}")
            return True

    def _handle_get_offline_messages(self, conn: socket.socket, uid: str) -> bool:
        """
        处理获取离线消息请求

        Args:
            :param conn: 客户端连接
            :param uid: 用户ID

        Returns:
            :return 是否继续保持连接
        """
        try:
            # 从数据库查询离线消息
            offline_messages = self.db.select_sql(
                "offline_chat_history",
                'content, from_user, to_user, send_time, type',
                f"to_user={uid}"
            )

            # 处理图片消息的base64编码
            processed_messages = []
            for message in offline_messages:
                content, from_user, to_user, send_time, msg_type = message

                if msg_type == "image":
                    # 将二进制图片数据转换为base64字符串
                    content = base64.b64encode(content).decode()

                processed_messages.append((content, from_user, to_user, send_time, msg_type))

            # 发送离线消息给客户端
            net.send_packet(conn, "offline_messages", processed_messages)

            # 删除已发送的离线消息
            self.db.delete_chat_history_from_db(uid)

            logger.debug(f"已发送 {len(processed_messages)} 条离线消息给用户 {uid}")
            return True

        except Exception as e:
            logger.error(f"获取离线消息时出错: {e}")
            return True

    def _handle_register_account(self, conn: socket.socket, message: Dict[str, Any]) -> bool:
        """
        处理用户注册请求

        Args:
            :param conn: 客户端连接
            :param message: 注册请求消息

        Returns:
            :return 是否继续保持连接
        """
        try:
            payload = message['payload']
            username = payload['username']
            password = payload['password']

            # 检查用户名是否已存在
            if self.db.check_account_exists(username):
                net.send_packet(conn, "register_result", {"success": False})
                logger.info(f"注册失败: 用户名 {username} 已存在")
                return True

            # 创建用户账号
            result = self.db.add_account(username, password, username, time.time())

            if result[0][0]:  # 注册成功
                net.send_packet(conn, "register_result", {
                    "success": True,
                    'uid': result[0][0],
                    'username': username,
                    'password': password
                })
                logger.info(f"用户 {username} 注册成功，UID: {result[0][0]}")
            else:  # 注册失败
                net.send_packet(conn, "register_result", {"success": False})
                logger.error(f"用户 {username} 注册失败")

            return True

        except KeyError as e:
            logger.error(f"注册请求格式错误: {e}")
            net.send_packet(conn, "register_result", {"success": False})
            return True

    def _handle_add_friend(self, conn: socket.socket, message: Dict[str, Any], uid: str) -> bool:
        """
        处理好友请求

        Args:
            :param conn: 客户端连接
            :param message: 好友请求消息
            :param uid: 请求者用户ID

        Returns:
            :return 是否继续保持连接
        """
        try:
            payload = message['payload']
            friend_id_type = payload['friend_id_type']
            friend_id = payload['friend_id']
            verify_token = payload['verify_token']

            if friend_id_type == "username":
                return self._add_friend_by_username(conn, friend_id, verify_token, uid)
            elif friend_id_type == "uid":
                return self._add_friend_by_uid(conn, friend_id, verify_token, uid)
            else:
                net.send_packet(conn, "add_friend_result", {
                    "success": False,
                    "reason": "invalid_friend_id_type"
                })
                return True

        except KeyError as e:
            logger.error(f"好友请求格式错误: {e}")
            net.send_packet(conn, "add_friend_result", {
                "success": False,
                "reason": "internal_error"
            })
            return True

    def _add_friend_by_username(self, conn: socket.socket, username: str, verify_token: str, uid: str) -> bool:
        """
        通过用户名添加好友

        Args:
            :param conn: 客户端连接
            :param username: 好友用户名
            :param verify_token: 验证令牌
            :param uid: 请求者ID

        Returns:
            :return 是否继续保持连接
        """
        # 查询目标用户的验证令牌
        res = self.db.select_sql("user", "friend_token", f"username='{username}'")
        if not res:
            net.send_packet(conn, "add_friend_result", {
                "success": False,
                "reason": "user_not_found"
            })
            return True

        friend_token = res[0][0]
        if friend_token != verify_token:
            net.send_packet(conn, "add_friend_result", {
                "success": False,
                "reason": "verify_token_error"
            })
            return True

        # 获取好友信息
        friend_uid = self.db.get_uid_by_username(username)
        friend_name = self.db.get_name_by_uid(friend_uid)

        # 发送成功响应
        net.send_packet(conn, "add_friend_result", {
            "success": True,
            "friend_uid": friend_uid,
            "friend_username": username,
            "friend_name": friend_name
        })

        # 发送好友验证完成消息
        self._send_friend_welcome_messages(uid, friend_uid)

        logger.info(f"用户 {uid} 通过用户名成功添加好友 {friend_uid}")
        return True

    def _add_friend_by_uid(self, conn: socket.socket, friend_uid: str, verify_token: str, uid: str) -> bool:
        """
        通过UID添加好友

        Args:
            :param conn: 客户端连接
            :param friend_uid: 好友用户ID
            :param verify_token: 验证令牌
            :param uid: 请求者ID

        Returns:
            :return 是否继续保持连接
        """
        # 查询目标用户的验证令牌
        res = self.db.select_sql("user", "friend_token", f"id={friend_uid}")
        if not res:
            net.send_packet(conn, "add_friend_result", {
                "success": False,
                "reason": "friend_not_found"
            })
            return True

        friend_token = res[0][0]
        if friend_token != verify_token:
            net.send_packet(conn, "add_friend_result", {
                "success": False,
                "reason": "verify_token_error"
            })
            return True

        # 检查被请求方是否在线
        if str(friend_uid) not in net.logged_in_clients:
            net.send_packet(conn, "add_friend_result", {
                "success": False,
                "reason": "friend_not_online"
            })
            return True

        # 获取请求方信息
        requester_username = self.db.get_username_by_uid(uid)
        requester_name = self.db.get_name_by_uid(uid)

        # 通知被请求方
        target_conn = net.logged_in_clients[str(friend_uid)]
        net.send_packet(target_conn, "add_friend_result", {
            "success": True,
            "friend_uid": uid,
            "friend_username": requester_username,
            "friend_name": requester_name
        })

        # 通知请求方
        net.send_packet(conn, "add_friend_result", {
            "success": True,
            "friend_uid": friend_uid,
            "friend_username": self.db.get_username_by_uid(friend_uid),
            "friend_name": self.db.get_name_by_uid(friend_uid)
        })

        # 发送好友验证完成消息
        self._send_friend_welcome_messages(uid, friend_uid)

        logger.info(f"用户 {uid} 通过UID成功添加好友 {friend_uid}")
        return True

    def _send_friend_welcome_messages(self, uid1: str, uid2: str) -> None:
        """
        发送好友添加成功的欢迎消息

        Args:
            :param uid1: 用户1的ID
            :param uid2: 用户2的ID
        """
        current_time = time.time()

        # 给用户1发送消息（来自用户2）
        welcome_msg_1 = "我通过了你的好友验证请求，现在我们可以开始聊天了"
        if uid1 in net.logged_in_clients:
            net.send_packet(net.logged_in_clients[uid1], "new_message", {
                "from_user": uid2,
                "message": welcome_msg_1,
                "time": current_time,
                "need_update_contact": False
            })
        else:
            self.db.save_chat_history(welcome_msg_1, uid2, uid1)

        # 给用户2发送消息（来自用户1）
        welcome_msg_2 = "你通过了我的好友验证请求，现在我们可以开始聊天了"
        if uid2 in net.logged_in_clients:
            net.send_packet(net.logged_in_clients[uid2], "new_message", {
                "from_user": uid1,
                "message": welcome_msg_2,
                "time": current_time,
                "need_update_contact": False
            })
        else:
            self.db.save_chat_history(welcome_msg_2, uid1, uid2)

    def _handle_change_friend_token(self, message: Dict[str, Any], uid: str) -> bool:
        """
        处理修改好友验证令牌请求

        Args:
            :param message: 请求消息
            :param uid: 用户ID

        Returns:
            :return 是否继续保持连接
        """
        try:
            new_token = message['payload']['new_friend_token']
            self.db.change_friend_token(uid, new_token)
            logger.info(f"用户 {uid} 更新了好友验证令牌")
            return True
        except KeyError as e:
            logger.error(f"修改好友令牌请求格式错误: {e}")
            return True

    def _handle_get_friend_token(self, conn: socket.socket, uid: str) -> bool:
        """
        处理获取好友验证令牌请求

        Args:
            :param conn: 客户端连接
            :param uid: 用户ID

        Returns:
            :return 是否继续保持连接
        """
        try:
            res = self.db.select_sql("user", "friend_token", f"id={uid}")
            friend_token = res[0][0] if res else None

            net.send_packet(conn, "friend_token_result", {"friend_token": friend_token})
            logger.debug(f"已发送好友令牌给用户 {uid}")
            return True

        except Exception as e:
            logger.error(f"获取好友令牌时出错: {e}")
            net.send_packet(conn, "friend_token_result", {"friend_token": None})
            return True

    @staticmethod
    def _cleanup_client_connection(conn: socket.socket, uid: Optional[str]) -> None:
        """
        清理客户端连接资源

        Args:
            :param conn: 客户端连接对象
            :param uid: 用户ID（如果已登录）
        """
        if conn in net.clients:
            if uid and str(uid) in net.logged_in_clients:
                logger.debug(f"用户 {uid} 已登出")
                del net.logged_in_clients[str(uid)]
            net.remove_client(conn)


def stop_server() -> None:
    """
    停止服务器并清理资源
    关闭所有客户端连接和数据库连接
    """
    logger.info("正在停止服务器...")

    # 关闭所有客户端连接
    for client in net.clients:
        try:
            client.close()
        except Exception as e:
            logger.critical(e, exc_info=True)

    # 关闭服务器套接字
    if net.sock:
        try:
            net.sock.shutdown(socket.SHUT_RDWR)
            net.sock.close()
        except Exception as e:
            logger.critical(e, exc_info=True)

    # 关闭数据库连接
    if server_instance:
        server_instance.db.close()

    logger.info("服务器已停止")
    sys.exit(0)


def print_server_ascii() -> None:
    """打印服务器启动时的ASCII艺术字"""
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
    print(color_helper.green(server_ascii))


def execute_server_command(command: str) -> bool:
    """
    执行服务器控制台命令

    Args:
        :param command: 用户输入的命令

    Returns:
        :return 是否继续运行服务器（False表示应该停止）
    """
    global server_instance

    command = command.strip()

    if command.startswith("stop"):
        stop_server()
        return False

    elif command.startswith("status"):
        logger.info("服务器状态信息:")
        logger.info(f"当前连接的客户端: {len(net.clients)} 个")
        logger.info(f"已登录的用户: {len(net.logged_in_clients)} 个")
        logger.info(f"客户端连接对象: {net.clients}")
        logger.info(f"已登录用户列表: {list(net.logged_in_clients.keys())}")

    elif command.startswith("help"):
        print_help_message()

    elif command.startswith("check account exists "):
        username = command[21:].strip()
        if username:
            exists = server_instance.db.check_account_exists(username)
            logger.info(f"用户 '{username}' {'存在' if exists else '不存在'}")
        else:
            logger.warning("请指定用户名")

    elif command.startswith("get offline messages "):
        uid_str = command[21:].strip()
        if uid_str:
            try:
                get_and_display_offline_messages(uid_str)
            except ValueError:
                logger.warning("用户ID必须是数字")
        else:
            logger.warning("请指定用户ID")

    elif command == "":
        # 空命令，不执行任何操作
        pass

    else:
        logger.warning(f"未知命令: '{command}'，输入 'help' 查看可用命令")

    return True


def print_help_message() -> None:
    """打印帮助信息"""
    help_text = """
可用命令列表:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
stop                           - 停止服务器
status                         - 显示服务器状态信息
check account exists <用户名>   - 检查指定用户是否存在
get offline messages <用户ID>   - 获取指定用户的离线消息
help                           - 显示此帮助信息
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """
    print(color_helper.cyan(help_text))


def get_and_display_offline_messages(uid: str) -> None:
    """
    获取并显示指定用户的离线消息

    Args:
        :param uid: 用户ID字符串
    """
    global server_instance

    try:
        # 查询离线消息
        offline_messages = server_instance.db.select_sql(
            "offline_chat_history",
            'content, from_user, to_user, send_time, type',
            f"to_user={uid}"
        )

        if not offline_messages:
            logger.info(f"用户 {uid} 没有离线消息")
            return

        logger.info(f"用户 {uid} 的离线消息 (共{len(offline_messages)}条):")

        # 处理并显示每条消息
        processed_messages = []
        for i, message in enumerate(offline_messages, 1):
            content, from_user, to_user, send_time, msg_type = message

            # 处理图片消息的显示
            if msg_type == "image":
                try:
                    # 将二进制数据转换为base64用于显示
                    content_display = f"[图片消息，大小: {len(content)} 字节]"
                    content = base64.b64encode(content).decode()
                except Exception as e:
                    content_display = f"[图片消息解码失败: {e}]"
            else:
                content_display = content

            # 格式化时间
            time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(send_time))

            logger.info(f"  {i}. [{time_str}] 来自用户{from_user}: {content_display} (类型: {msg_type})")
            processed_messages.append((content, from_user, to_user, send_time, msg_type))

    except Exception as e:
        logger.error(f"获取离线消息时出错: {e}")


def main() -> None:
    """
    服务器主函数
    初始化服务器并启动控制台界面
    """
    global net, server_listen_thread, server_instance

    try:
        # 打印启动界面
        print_server_ascii()
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

        # 初始化服务器实例
        logger.info("正在启动服务器...")
        server_instance = Server()

        # 启动网络监听线程
        server_listen_thread = threading.Thread(
            target=net.listen_clients,
            args=(server_instance.handle_client,),
            daemon=True
        )
        server_listen_thread.start()

        logger.info("服务器启动成功！")
        logger.info("按回车键进入服务器控制台...")
        input()

        # 进入服务器控制台循环
        logger.info("欢迎使用 WritePapers 服务器控制台")
        logger.info("输入 'help' 查看可用命令")

        while True:
            try:
                # 短暂延迟以减少CPU占用
                time.sleep(0.03)

                # 获取用户输入的命令
                command = input(color_helper.green("WritePapers Server >>> "))

                # 执行命令，如果返回False则退出循环
                if not execute_server_command(command):
                    break

            except EOFError:
                # 处理Ctrl+D或输入流结束
                logger.info("检测到输入结束，正在停止服务器...")
                stop_server()
                break
            except KeyboardInterrupt:
                # 处理Ctrl+C中断
                logger.info("检测到键盘中断，正在停止服务器...")
                stop_server()
                break

    except KeyboardInterrupt:
        # 处理启动过程中的中断
        stop_server()
    except Exception as e:
        # 处理其他异常
        logger.error(f"服务器运行时发生严重错误: {e}")
        traceback.print_exc()
        stop_server()


if __name__ == "__main__":
    main()
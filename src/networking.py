#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2025/6/2
# @File    : networking.py
# @Software: PyCharm
# @Desc    :
# @Author  : Kevin Chang
import socket
import json
import threading

import paperlib as lib
import structlog

"""
    网络部分的模块
    一个标准的客户端数据包应该是json格式，具体这样的：
    {
        "type": "类型",
        "token": "TEMP_TOKEN_NEED_CHANGE", //暂时这样，以后再改成单次登录由服务端发回的一次性token,登录时token为"LOGIN"
        "payload": {
            "key":"value"
        }
    }

    服务端数据包应去除token,格式如下
    {
        "type": "类型",
        "payload": {
            "key":"value"
        }
    }
    --------------------------------------------------------------------------------------------------------------------
    以下为不同类型的数据包格式
    模板：
    {
        "type": "类型",
        "token": "TEMP_TOKEN_NEED_CHANGE",
        "payload": {
            "key":"value"
        }
    }
    客户端收到的新消息（S2C）：
    {
        "type": "new_message",
        "payload": {
            "from_user": 0,
            "message": "Hello, World!"
        }
    }
    客户端发送消息（C2S）:
    {
        "type": "send_message",
        "token": "TEMP_TOKEN_NEED_CHANGE",
        "payload":{
            "to_user": 0,
            "message": "Hello!"
        }
    }
"""


def _get_logger():
    return structlog.get_logger()


logger = _get_logger()
temp_xml_dir = "data/"


class ServerNetwork:
    def __init__(self):
        # 全局变量：服务器的ip和端口
        self.server_host = lib.read_xml("server/ip", temp_xml_dir)
        self.server_port = int(lib.read_xml("server/port", temp_xml_dir))
        # 全局变量：存储所有在线客户端的连接
        self.clients = []
        # 全局变量：存储已登录的客户端
        self.logged_in_clients = {}
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.server_host, self.server_port))


    def listen_clients(self, callback):
        """
        监听客户端
        Args:
            :param callback: 客户端处理函数
        Returns:
            :return: None
        """
        logger.debug(self.sock)
        self.sock.listen()
        while True:
            conn, addr = self.sock.accept()
            self.clients.append(conn)
            threading.Thread(target=callback, args=(conn, addr), daemon=True).start()
    @staticmethod
    def send_packet(conn, message_type, payload):
        """
        发送数据包
        Args:
            :param conn: 客户端连接
            :param message_type: 数据包的类型
            :param payload: 数据包的内容
        Returns:
            :return: None
        """
        packet = {
            "type": message_type,
            "payload": payload
        }
        packet = json.dumps(packet)
        packet_bytes = packet.encode("utf-8")
        # 先发送4字节的数据长度
        length = len(packet_bytes)
        conn.sendall(length.to_bytes(4, byteorder='big'))
        # 再发送数据内容
        conn.sendall(packet_bytes)
        logger.debug("Message sent:" + packet)

    def remove_client(self, conn):
        """
        线程安全的移除客户端连接
        Args:
            :param conn: 要移除的客户端
        Returns:
            :return: None
        """
        if conn in self.clients:
            self.clients.remove(conn)
            conn.close()
            logger.debug(f"Client removed: {conn}")
        else:
            logger.warning("Trying to remove a unhandled client")

if __name__ == '__main__':
    """调试"""
    # logger = structlog.get_logger()
    net = ServerNetwork()


    def handle_client(conn, addr):
        logger.info(f"New client connected: {addr}")
        net.send_packet(conn, "server_hello", {"content": "Hello, world!"})


    net.listen_clients(handle_client)
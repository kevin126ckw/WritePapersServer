#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2025/6/2
# @File    : self.py
# @Software: PyCharm
# @Desc    :
# @Author  : Kevin Chang
import sqlite3,traceback
import time
import structlog

logger = structlog.get_logger()

class Database:
    def __init__(self):
        self.conn = None
        self.cursor = None
        # 全局缓存字典
        self.uid_cache = {}

    def connect(self, file):
        """
        建立数据库连接
        Args:
            :param file: 文件路径
        """
        try:
            self.conn = sqlite3.connect(file , check_same_thread=False)
            self.cursor = self.conn.cursor()
        except sqlite3.Error as e:
            logger.error(f"Error connecting to database: {e}")
            logger.traceback(traceback.format_exc())

    def run_sql(self, command, params=None):
        """
        执行 SQL 命令
        Args:
            :param command: SQL命令
            :param params: 参数
        """
        try:
            if params:
                self.cursor.execute(command, params)  # 参数化查询
            else:
                self.cursor.execute(command)
            self.conn.commit()  # 提交事务
        except sqlite3.Error as e:
            logger.error(f"执行 SQL 失败: {e} 欲执行的SQL语句：{command}")
        return self.cursor.fetchall()

    def insert_sql(self, table, columns, values):
        """
        插入数据
        Args:
            :param table: 表
            :param columns: 列
            :param values: 值
        """
        try:
            # 使用 ? 占位符代替直接拼接的 values
            placeholders = ",".join(["?"] * len(values))
            sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
            self.cursor.execute(sql, tuple(values))
            self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"插入数据失败: {e}")
            logger.traceback(traceback.format_exc())

    def select_sql(self, table, columns, condition=None):
        """
        查询数据
        Args:
            :param table: 表
            :param columns: 列
            :param condition: 条件
        """
        try:
            sql = f"SELECT {columns} FROM {table}"
            if condition:
                sql += f" WHERE {condition}"
            result = self.run_sql(sql)
            return result
        except sqlite3.Error as e:
            logger.error(f"查询数据失败: {e}")
            logger.traceback(traceback.format_exc())
            return None

    def close(self):
        """
        关闭数据库连接
        """
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

    def commit(self):
        """
        提交事务
        """
        if self.conn:
            self.conn.commit()
    # ------------------------------------------------------------------------------------------------------------------
    def add_account(self, username, password, name, register_time):
        """
        添加账号
        Args:
            :param username: 用户名
            :param password: 密码
            :param name: 昵称
            :param register_time: 注册时间
        """
        """register_time应为unix时间戳"""
        self.insert_sql("user", "username, password, name, register_time",
                            [username, password, name, register_time])
        return self.select_sql("user", "id", f"username='{username}'")

    def delete_account(self, uid):
        """
        删除账号
        Args:
            :param uid: UID
        """
        debug = False  # 是否删除数据库中的自增id
        self.run_sql("DELETE FROM main.user WHERE id=?", [uid])
        if debug:
            # 修复条件拼接问题，防止SQL注入
            user_id = self.select_sql("user", "id", f"id='{uid}'")
            if user_id:
                self.run_sql("UPDATE main.sqlite_sequence SET seq=? WHERE name='user'", [user_id[0][0] - 1])

    def change_account_password(self, uid, password):
        """
        修改账号密码
        Args:
            :param uid: UID
            :param password: 新密码
        """
        self.run_sql("UPDATE main.user SET password=? WHERE id=?", [password, uid])

    def check_account_password(self, username, password):
        """
        检查账号密码
        Args:
            :param username: UID
            :param password: 密码
        Returns:
        :return bool: 结果
        """
        result = self.select_sql("main.user", "*", f"username='{username}'")
        try:
            if result[0][2] == password:
                return True
            else:
                return False
        except IndexError:
            return False

    def save_chat_history(self, message, from_user, to_user):
        """
        保存聊天记录
        Args:
            :param message: 消息内容
            :param from_user: 发送方
            :param to_user: 接收方
        """
        self.insert_sql("offline_chat_history", "content, from_user, to_user, type, send_time",
                            [message, from_user, to_user, "text", time.time()])

    def delete_chat_history_from_db(self, uid):
        """
        删除用户全部离线聊天记录
        Args:
            :param uid: 被删除的用户的UID
        """
        self.run_sql("DELETE FROM main.offline_chat_history WHERE to_user=?", [uid])

    def get_uid_by_username(self, username):
        """
        根据用户名获取UID
        Args:
            :param username: 用户名
        Returns:
            :return: int:uid
        """
        # 检查缓存中是否存在该用户名，并且缓存时间在1分钟内
        if username in self.uid_cache:
            cached_uid, cached_time = self.uid_cache[username]
            if time.time() - cached_time < 60:  # 1分钟内
                return cached_uid
        result = self.select_sql("user", "id", f"username='{username}'")
        uid = result[0][0] if result else None
        # 更新缓存
        self.uid_cache[username] = (uid, time.time())
        return uid

    def get_name_by_uid(self, uid):
        """
        根据UID获取昵称
        Args:
            :param uid: UID
        Returns:
            :return: str: 昵称
        """
        try:
            result = self.select_sql("user", "name", f"id='{uid}'")
            return result[0][0]
            
        except Exception as e:
            print(e)
            print(traceback.format_exc())
            return None
if __name__ == "__main__":
    db = Database()
    db.connect("data/server.sqlite")
    db.check_account_password("temp", "admin")
        
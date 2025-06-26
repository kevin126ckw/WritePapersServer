#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2025/6/2
# @File    : self.py
# @Software: PyCharm
# @Desc    :
# @Author  : Kevin Chang
import sqlite3,traceback
import time
class Database:
    def __init__(self):
        self.conn = None
        self.cursor = None
        # 全局缓存字典
        self.uid_cache = {}

    def connect(self, file):
        """建立数据库连接"""
        try:
            self.conn = sqlite3.connect(file , check_same_thread=False)
            self.cursor = self.conn.cursor()
        except sqlite3.Error as e:
            print(f"连接数据库失败: {e}")
            print(traceback.format_exc())

    def run_sql(self, command, params=None):
        """执行 SQL 命令"""
        try:
            if params:
                self.cursor.execute(command, params)  # 参数化查询
            else:
                self.cursor.execute(command)
            self.conn.commit()  # 提交事务
        except sqlite3.Error as e:
            print(f"执行 SQL 失败: {e}")
            print(f"欲执行的SQL语句：{command}")
        return self.cursor.fetchall()

    def insert_sql(self, table, columns, values):
        """插入数据"""
        try:
            # 使用 ? 占位符代替直接拼接的 values
            placeholders = ",".join(["?"] * len(values))
            sql = f"INSERT INTO {table} ({columns}) VALUES ({placeholders})"
            self.cursor.execute(sql, tuple(values))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"插入数据失败: {e}")
            print(traceback.format_exc())

    def select_sql(self, table, columns, condition=None):
        """查询数据"""
        try:
            sql = f"SELECT {columns} FROM {table}"
            if condition:
                sql += f" WHERE {condition}"
            result = self.run_sql(sql)
            return result
        except sqlite3.Error as e:
            print(f"查询数据失败: {e}")
            print(traceback.format_exc())
            return None

    def close(self):
        """关闭数据库连接"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

    def commit(self):
        if self.conn:
            self.conn.commit()
    # ------------------------------------------------------------------------------------------------------------------
    def add_account(self, username, password, name, register_time):
        """添加账号"""
        """register_time应为unix时间戳"""
        self.insert_sql("user", "username, password, name, register_time",
                            [username, password, name, register_time])

    def delete_account(self, uid):
        """删除账号"""
        debug = False  # 是否删除数据库中的自增id
        self.run_sql("DELETE FROM main.user WHERE id=?", [uid])
        if debug:
            # 修复条件拼接问题，防止SQL注入
            user_id = self.select_sql("user", "id", f"id='{uid}'")
            if user_id:
                self.run_sql("UPDATE main.sqlite_sequence SET seq=? WHERE name='user'", [user_id[0][0] - 1])

    def change_account(self, uid, password):
        """修改账号"""
        self.run_sql("UPDATE main.user SET password=? WHERE id=?", [password, uid])

    def check_account_password(self, uid, password):
        """检查账号密码"""
        result = self.select_sql("user", "*", f"id='{uid}'")
        if result[0][2] == password:
            return True
        else:
            return False

    def save_chat_history(self, message, from_user, to_user):
        """保存聊天记录"""
        self.insert_sql("offline_chat_history", "content, from_user, to_user, type, send_time",
                            [message, from_user, to_user, "text", time.time()])

    def delete_chat_history_from_db(self, uid):
        """删除聊天记录"""
        self.run_sql("DELETE FROM main.offline_chat_history WHERE to_user=?", [uid])

    def serverside_get_uid_by_username(self, username):
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

    def server_get_name_by_uid(self, uid):
        try:
            result = self.select_sql("user", "name", f"id='{uid}'")
            return result[0][0]
            
        except Exception as e:
            print(e)
            print(traceback.format_exc())
            return None
    def client_get_name_by_uid(self, uid):
        try:
            result = self.select_sql("contact", "name", f"id='{uid}'")
            return result[0][0]
        except Exception as e:
            print(e)
            print(traceback.format_exc())
            return None
    def save_contact(self, uid, username, name, mem):
        self.insert_sql("contact", "id, username, name, mem", [uid, username, name, mem])
        
        
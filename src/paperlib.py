#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2025/5/1
# @File    : paperlib.py
# @Software: PyCharm
# @Desc    :
# @Author  : Kevin Chang
from xml.etree import ElementTree
import os


def read_xml(keyword, path="../data/"):
    """
    从指定侧的XML文件中读取对应关键字的值

    通过解析项目data目录下的server.xml文件，使用XPath查找指定关键字的文本内容。
    若XML结构不符合预期或关键字不存在，将抛出可追踪的异常。

    Args:
        :param keyword: 要查找的XML元素名称，对应xml文件中的标签名
        :param path: server.xml的相对路径
    Returns:
        str: 匹配到的XML元素文本内容

    Raises:
        ValueError: 当指定的关键字在XML中不存在或XML格式不符合预期时抛出

    """
    try:
        # 构建XML文件绝对路径：当前文件目录的上层data目录 + 参数指定的文件名
        xml_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f'{path}server.xml')

        # 解析XML文档并获取根节点
        tree = ElementTree.parse(xml_path)
        root = tree.getroot()

        # 使用XPath语法递归搜索指定关键字节点
        return root.find(f".//{keyword}").text
    except AttributeError as e:
        # 转换底层解析异常为更有业务意义的错误类型，保留原始异常堆栈信息
        raise ValueError(f"Keyword '{keyword}' not found in XML or invalid format.") from e


#!/usr/bin/env python3
# encoding:utf-8
# 字母'a'重复100万次, 生成 1000000B=1000000B/(1024B/KB)=976.56KB 纯文本数据
ch = 'a'
total_length = 1000000
for i in range(total_length):
    print(ch, end='')

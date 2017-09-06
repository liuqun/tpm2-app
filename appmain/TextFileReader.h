/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef TEXT_FILE_READER_H_
#define TEXT_FILE_READER_H_

#ifdef __cplusplus

#include <cstdio>
#include <string>

/// 从文本文件读取下一行内容
///
/// 输出字符串的末尾不包括原始的换行符'\n'
/// @param fpTextFileIn 文件指针
/// @param cLineDelimiter 换行符
/// @param sLineOut 输出字符串
/// @return std::string 引用sLineOut
/// @throws std::ios::failure 读取硬盘或SD等卡存储介质时IO操作失败. 参见C++头文件`#include<ios>`
const std::string& GetNextLineFromTextFile(FILE *fpTextFileIn, std::string& sLineOut, char cLineDelimiter='\n');

#endif // __cplusplus
#endif // TEXT_FILE_READER_H_

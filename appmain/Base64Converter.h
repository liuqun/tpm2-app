/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef BASE64_CONVERTER_H_
#define BASE64_CONVERTER_H_

#include <stdio.h>

#ifndef __cplusplus
extern "C" {
#endif // __cplusplus

/// 向标准文件打印 Base64 文本
void PrintBase64TextFromBinaryData(FILE *fpOut, const void *dataIn, unsigned int length);

#ifndef __cplusplus
} // end of extern "C"
#endif // __cplusplus

// 以上 API 函数为 C 语言接口函数
// 以下 API 函数为 C++ 接口

#ifdef __cplusplus

#include <string>
#include <vector>

/// 生成 Base64 C++ 字符串
void Base64TextFromBinaryData(std::string& sBase64TextOut, const void *dataIn, unsigned int length);

/// 解析 Base64 C 字符串
void BinaryDataFromBase64Text(std::vector<unsigned char>& dataOut, const char szBase64TextIn[]);

#endif // __cplusplus

#endif // BASE64_CONVERTER_H_

/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <cstdlib>
#include <cassert>
#include <string>
using std::string;
#include "Base64Converter.h"

// 输出: 文本字符串 sBase64TextOut; 输入: 二进制数据 dataIn
void Base64TextFromBinaryData(std::string& sBase64TextOut, const void *dataIn, unsigned int length)
{
    const char base[64] = // base64编码映射表
    {   'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
        'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
        'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
    };
    const unsigned char *data = (const unsigned char *)dataIn;
    unsigned int a, b, c, d;
    unsigned int i;
    unsigned int j;
    char *szCache;
    const unsigned int n = 1 + (2 + length)/3 * 4; // 可以事先求得 base64 编码的最终输出长度
    szCache = (char *)malloc(n);
    assert(szCache);
    if (!szCache)
    {
        return; // Error: 内存耗尽
    }
    szCache[0] = '\0';
    j = 0;
    for (i=3; i<=length; i+=3)
    {
        a = (unsigned int) (data[i-3] >> 2);
        b = (unsigned int) ((0x03 & data[i-3])<<4) | (data[i-2]>>4);
        c = (unsigned int) ((0x0F & data[i-2])<<2) | (data[i-1]>>6);
        d = (unsigned int) (0x3F & data[i-1]);
        szCache[j++] = base[a];
        szCache[j++] = base[b];
        szCache[j++] = base[c];
        szCache[j++] = base[d];
    }

    i -= 3;
    if (i == length)
    {
        goto FINISH;
    }

    // 可能剩余 2 字节或剩余 1 字节未处理, 对应 i 的取值可能等于 len-2 或 len-1
    a = (unsigned int) (data[i] >> 2);
    szCache[j++] = base[a];
    b = (unsigned int) ((0x03 & data[i]) << 4);
    if (length-i <= 1) {
        szCache[j++] = base[b];
        szCache[j++] = '=';
        szCache[j++] = '=';
        goto FINISH;
    }
    b |= (unsigned int) (data[i+1] >> 4);
    c = (unsigned int) ((0x0F & data[i+1]) << 2);
    szCache[j++] = base[b];
    szCache[j++] = base[c];
    szCache[j++] = '=';

FINISH:
    szCache[j++] = '\0';
    sBase64TextOut.assign(szCache, n);
    free(szCache);
}

// (内部函数) 反查 Base64 映射表
static int Base64DecodeMap(char ch)
{
    if (ch >= 'A' && ch <='Z')
    {
        return (ch - 'A');
    }
    if (ch >= 'a' && ch <='z')
    {
        return (26 + ch - 'a');
    }
    if (isdigit(ch))
    {
        return (52 + ch - '0');
    }

    int result;
    switch (ch)
    {
    case '+':
        result = 62;
        break;
    case '/':
        result = 63;
        break;
    default:
        result = 0;
        break;
    }
    return result;
}

#include <cstring>
#include <vector>
using std::vector;

// 输出: 二进制数据 dataOut; 输入: 以 '\0' 结尾的 C 语言文本字符串 szBase64TextIn[]
void BinaryDataFromBase64Text(std::vector<unsigned char>& dataOut, const char szBase64TextIn[])
{
    const unsigned int length = std::strlen(szBase64TextIn);
    if ((length % 4) >= 1)
    {
        // Error: Invalid input
        return;
    }

    unsigned int a, b, c, d;
    unsigned char raw[3];
    unsigned int i;
    for (i=0; i<=length; i+=4)
    {
        a = Base64DecodeMap(szBase64TextIn[i]);
        b = Base64DecodeMap(szBase64TextIn[i+1]);
        raw[0] = (a << 2) | (b >> 4);
        dataOut.push_back(raw[0]);

        if ('=' == szBase64TextIn[i+2])
        {
            break;
        }
        c = Base64DecodeMap(szBase64TextIn[i+2]);
        raw[1] = (0xF0 & (b << 4)) | (c >> 2);
        dataOut.push_back(raw[1]);

        if ('=' == szBase64TextIn[i+3])
        {
            break;
        }
        d = Base64DecodeMap(szBase64TextIn[i+3]);
        raw[2] = (0xC0 & (c << 6)) | d;
        dataOut.push_back(raw[2]);
    }
}

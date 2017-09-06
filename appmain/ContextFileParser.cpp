/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <cstdio>
#include <string>
using std::string;
#include <vector>
using std::vector;
#include <map>
using std::map;
#include <sapi/tpm20.h>
#include "ContextFileParser.h"
#include "TextFileReader.h"
#include "Base64Converter.h"

// 内部函数声明
static UINT64 UINT64FromText(std::string text);
static UINT32 UINT32FromText(std::string text);

/* 排版格式: 以下函数均使用4个空格缩进，不使用Tab缩进 */

// 构造函数
ContextFileParser::ContextFileParser()
{
    m_szFileName = "context.csv";
}

// 构造函数2: 通过参数指定文件名
ContextFileParser::ContextFileParser(const char *szFileName)
{
    if (!szFileName) // 不允许调用者传入NULL指针
    {
        return; // TODO: Raise/throw an std::invalid_argument() exception. (发现无效参数时抛出 std::invalid_argument)
    }
    m_szFileName = szFileName;
}

// 指定文件名
void ContextFileParser::setFileName(const char *szFileName)
{
    if (!szFileName) // 不允许调用者传入NULL指针
    {
        return; // TODO: Raise/throw an std::invalid_argument() exception. (发现无效参数时抛出 std::invalid_argument)
    }
    m_szFileName = szFileName;
}

// 解析当前文件, 取出文件解析结果
void ContextFileParser::fetch(TPMS_CONTEXT& contextOut)
{
    const char *CheckList[] = {"sequence", "handle", "hierarchy", "blob", NULL};
    map<string, string> dictionary;
    string line;
    std::size_t pos;
    string k;
    string v;
    FILE *fp;

    fp = fopen(m_szFileName, "r");
    if (!fp) // Error: Cannot write output file!
    {
        fprintf(stderr, "Error: 找不到文件%s!\n", m_szFileName);
        return; // TODO: Raise/throw an exception
    }

    while (!feof(fp))
    {
        line.clear();
        GetNextLineFromTextFile(fp, line);
        pos = line.find(",");
        if (string::npos == pos)
        {
            continue; // 任何不含逗号(',')的行都将被看作无效行直接跳过
        }
        k = line.substr(0, pos);
        v = line.substr(pos+1, string::npos);
        dictionary[k] = v; // NOTE: 如果列表出现重复项, 将直接覆盖旧值
    }
    fclose(fp);

    // 检查文件是否漏行
    for (int i=0; CheckList[i]; i++)
    {
        if (dictionary.count(CheckList[i]) < 1)
        {
            fprintf(stderr, "Error: %s文件内容缺少%s字段!\n", m_szFileName, CheckList[i]);
            return; // TODO: Raise/throw an exception
        }
    }

    contextOut.sequence = UINT64FromText(dictionary["sequence"]);
    contextOut.savedHandle = UINT32FromText(dictionary["handle"]);
    contextOut.hierarchy = UINT32FromText(dictionary["hierarchy"]);
    {
        const string& sBase64Blob = dictionary["blob"];
        vector<unsigned char> buffer;

        BinaryDataFromBase64Text(buffer, sBase64Blob.c_str());
        contextOut.contextBlob.t.size = (UINT16) buffer.size();
        if (buffer.size() > sizeof(contextOut.contextBlob.t.buffer)) // (检查 contextBlob 结构体最大可容纳字节数, 避免指针访问越界)
        {
            contextOut.contextBlob.t.size = sizeof(contextOut.contextBlob.t.buffer);
        }
        memcpy(contextOut.contextBlob.t.buffer, buffer.data(), contextOut.contextBlob.t.size);
    }
    dictionary.clear();
}

// 以下为文本解析工具函数

#include <cstdlib>
#include <cctype>
#include <cerrno>
#include <limits.h>

// 自动识别10进制/16进制文本, 转换为无符号unsigned long long整数
// 16进制数字总是以"0x"开头
static unsigned long long int UnsignedLongLongIntFromText(const char *szText, unsigned int len)
{
    unsigned long long int value;
    char *endptr;
    int base;

    // 容错处理: 跳过字符串开头若干空白字符
    while (len>0 && isspace(*szText))
    {
        len--;
        szText++;
    }

    base = 10;
    if (len>2 && '0'==szText[0] && 'x'==tolower(szText[1]))
    {
        base = 16;
        szText += 2;
    }

    errno = 0;
    value = strtoull(szText, &endptr, base);
    if ((value >= ULLONG_MAX) || errno)
    {
        // TODO: Raise/throw an exception here?
    }
    return (value);
}

static UINT64 UINT64FromText(string text)
{
    return (UnsignedLongLongIntFromText(text.c_str(), text.length()));
}

static UINT32 UINT32FromText(string text)
{
    unsigned long long int value;
    value = UnsignedLongLongIntFromText(text.c_str(), text.length());
    if (value > 0xFFFFFFFF)
    {
        return (0xFFFFFFFF); // 32位无符号数溢出
    }
    return (value & 0xFFFFFFFF);
}

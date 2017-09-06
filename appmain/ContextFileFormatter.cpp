/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <cstdio>
#include <string>
using std::string;
#include <sapi/tpm20.h>
#include "ContextFileFormatter.h"
#include "Base64Converter.h"

// 内部函数声明
static void PrintNodeContext(FILE *fpOut, const TPMS_CONTEXT& nodeContext, const char *szDelimiter);

// 构造函数
ContextFileFormatter::ContextFileFormatter()
{
    m_szFileName = "context.csv";
    setLineDelimiter();
}

// 构造函数2
ContextFileFormatter::ContextFileFormatter(const char *szFileName)
{
    if (!szFileName) // 不允许调用者传入NULL指针
    {
        return; // TODO: Raise/throw an std::invalid_argument() exception. (发现无效参数时抛出 std::invalid_argument)
    }
    m_szFileName = szFileName;
    setLineDelimiter();
}

// 指定文件名
void ContextFileFormatter::setFileName(const char *szFileName)
{
    if (!szFileName) // 不允许调用者传入NULL指针
    {
        return; // TODO: Raise/throw an std::invalid_argument() exception. (发现无效参数时抛出 std::invalid_argument)
    }
    m_szFileName = szFileName;
}

// 指定换行分割标识
void ContextFileFormatter::setLineDelimiter(const char *szLineDelimiter)
{
    if (!szLineDelimiter) // 不允许调用者传入NULL指针
    {
        return; // TODO: Raise/throw an std::invalid_argument() exception. (发现无效参数时抛出 std::invalid_argument)
    }
    m_szLineDelimiter = szLineDelimiter;
}

// 创建输出文件, 然后调用子函数打印格式化输出文本
void ContextFileFormatter::output(const TPMS_CONTEXT& context)
{
    FILE *fp;

    fp = fopen(m_szFileName, "w");
    if (!fp) // Error: Cannot write output file!
    {
        return; // TODO: Raise/throw an exception
    }
    PrintNodeContext(fp, context, m_szLineDelimiter);
    fclose(fp);
}

// UINT64转文本字符串
static void TextFromUINT64(string& text, UINT64 u)
{
    char *sz;
    int n;
    const UINT32 high32 = (UINT32) (u>>32);
    const UINT32 low32 = (u&0xFFFFFFFF);
    sz=NULL;
    n = asprintf(&sz, "0x%08x%08x", high32, low32);
    text.clear();
    if ((n<=0) || !sz)
    {
        return;
    }
    text = sz;
    free(sz);
}

// UINT32转文本字符串
static void TextFromUINT32(string& text, UINT32 u)
{
    char *sz;
    int n;
    sz=NULL;
    n = asprintf(&sz, "0x%08x", u);
    if ((n<=0) || !sz)
    {
        return;
    }
    text = sz;
    free(sz);
}

// 依次转换各个结构体成员变量为纯文本字符串, 并输出至fpOut文件
static void PrintNodeContext(FILE *fpOut, const TPMS_CONTEXT& nodeContext, const char *szDelimiter)
{
    string sSequence;
    string sHandle;
    string sHierarchy;
    string sBlob;

    TextFromUINT64(sSequence, nodeContext.sequence);
    TextFromUINT32(sHandle, nodeContext.savedHandle);
    TextFromUINT32(sHierarchy, nodeContext.hierarchy);
    Base64TextFromBinaryData(sBlob, nodeContext.contextBlob.b.buffer, nodeContext.contextBlob.b.size);

    fputs("sequence,", fpOut);
    fputs(sSequence.c_str(), fpOut);
    fputs(szDelimiter, fpOut);

    fputs("handle,", fpOut);
    fputs(sHandle.c_str(), fpOut);
    fputs(szDelimiter, fpOut);

    fputs("hierarchy,", fpOut);
    fputs(sHierarchy.c_str(), fpOut);
    fputs(szDelimiter, fpOut);

    fputs("blob,", fpOut);
    fputs(sBlob.c_str(), fpOut);
    fputs(szDelimiter, fpOut);
}

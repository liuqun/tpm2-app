/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef CONTEXT_FILE_PARSER_H_
#define CONTEXT_FILE_PARSER_H_
#ifdef __cplusplus

#include <sapi/tpm20.h>

/// ContextFile(TPM 节点上下文缓存文件)格式解析器
class ContextFileParser
/// 文件格式由 ContextFileFormatter 定义
{
public:
    /// 构造函数格式1: 不带参数
    ContextFileParser();

    /// 构造函数格式2: 带文件名参数
    ///
    /// @param szFileName 文件名. TODO: 检查文件名长度, 检查是否存在特殊字符或中文字符编码, 然后小心处理各种坑.
    ContextFileParser(const char *szFileName);

    /// 设定文件名
    ///
    /// @param szFileName 文件名. TODO: 检查文件名长度, 检查是否存在特殊字符或中文字符编码, 然后小心处理各种坑.
    /// @throws std::invalid_argument 参见C++头文件`#include<stdexcept>`
    void setFileName(const char *szFileName);

    /// 取回文件解析结果
    ///
    /// (具体文件格式与 ContextFileFormatter 中所定义的一致)
    ///
    /// @param contextOut 输出参数. 指向结构体.
    /// @throws std::ios::failure 读取硬盘或SD等卡存储介质时IO操作失败. 参见C++头文件`#include<ios>`
    void fetch(TPMS_CONTEXT& contextOut);

private:
    const char *m_szFileName;
};

#endif // __cplusplus
#endif // CONTEXT_FILE_PARSER_H_

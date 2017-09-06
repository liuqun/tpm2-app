/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef CONTEXT_FILE_FORMATTER_H_
#define CONTEXT_FILE_FORMATTER_H_
#ifdef __cplusplus

#include <sapi/tpm20.h>

/// ContextFile(TPM 节点上下文缓存文件)格式化输出器
class ContextFileFormatter
/// 配套的解析器是: ContextFileParser
///
/// 详细的文本格式由C++代码实现决定, 此处提出以下几点实现建议
/// 1. 推荐使用可读的ASCII纯文本文件格式, 不推荐使用不可移植的二进制格式;
/// 2. 实现者根据实际情况自行约定采用base64编码格式或采用10进制/16进制字符串格式;
/// 3. 是否需要支持注释行应由实现者自己决定;
{
public:
    /// 构造函数格式1: 不带参数
    ContextFileFormatter();

    /// 构造函数格式2: 带文件名参数
    ///
    /// @param szFileName 文件名. TODO: 检查文件名长度, 检查是否存在特殊字符或中文字符编码, 然后小心处理各种坑.
    ContextFileFormatter(const char *szFileName);

    /// 设定文件名
    ///
    /// @param szFileName 文件名. TODO: 检查文件名长度, 检查是否存在特殊字符或中文字符编码, 然后小心处理各种坑.
    void setFileName(const char *szFileName);

    /// 设定行尾换行符
    ///
    /// @param szLineDelimiter 默认使用Unix风格换行符"\n". 特定场景下可以手动指定"\r\n"以兼容DOS/Windows
    void setLineDelimiter(const char *szLineDelimiter="\n");

    /// 文件格式化输出
    ///
    /// @param contextOut 输出参数. 指向结构体.
    ///
    /// TODO: 当磁盘已满无法写入时应抛出C++标准IO异常 std::ios::failure
    void output(const TPMS_CONTEXT& context);

private:
    const char *m_szFileName;
    const char *m_szLineDelimiter;
};

#endif // __cplusplus
#endif // CONTEXT_FILE_FORMATTER_H_

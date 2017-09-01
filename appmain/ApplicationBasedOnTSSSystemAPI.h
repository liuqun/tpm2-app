/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef CLIENT_CONTEXT_H_
#define CLIENT_CONTEXT_H_

#ifndef __cplusplus
#warning // Only C++ is supported. Please DON'T include this file from *.c!
#endif

#include <sapi/tpm20.h>

#ifdef __cplusplus

#include "ConnectionManager.h"

/// 客户端上下文初始化助手工具类
class ApplicationBasedOnTSSSystemAPI {
public:
    /// 构造函数
    ApplicationBasedOnTSSSystemAPI();
    /// 析构函数
    virtual ~ApplicationBasedOnTSSSystemAPI();
    /// 绑定连接管理器
    void bind(ConnectionManager& connectionManager);
    /// 解除已绑定的连接管理器
    void unbind();

protected:
    /// 取出指向 System API 上下文的指针
    void *getContextPtr();

private:
    size_t m_sysContextSize;
    TSS2_SYS_CONTEXT *m_sysContext;
};

#endif // __cplusplus
#endif // CLIENT_CONTEXT_H_

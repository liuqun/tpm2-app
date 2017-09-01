/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <cstdio>
#include <cstdlib> // malloc()/free()
#include <cassert> // assert()
#include <sapi/tpm20.h>
#include "ApplicationBasedOnTSSSystemAPI.h"

/* 排版格式: 以下代码均使用4个空格缩进，不使用Tab缩进 */

// 构造函数
ApplicationBasedOnTSSSystemAPI::ApplicationBasedOnTSSSystemAPI()
{
    m_sysContextSize = Tss2_Sys_GetContextSize(0);
    m_sysContext = (TSS2_SYS_CONTEXT *) malloc(m_sysContextSize);
    if (!m_sysContext)
    {
        fprintf(stderr, "Error: malloc() failed to allocate dynamic memory\n");
        exit (EXIT_FAILURE);
    }
    memset(m_sysContext, 0x00, m_sysContextSize);
}

// 析构函数
ApplicationBasedOnTSSSystemAPI::~ApplicationBasedOnTSSSystemAPI()
{
    /* 销毁 System API 上下文对象 */
    assert(m_sysContext);
    memset(m_sysContext, 0xFF, m_sysContextSize);
    free(m_sysContext);
}

// 取出指向 System API 上下文的指针
void *ApplicationBasedOnTSSSystemAPI::getContextPtr()
{
    return ((void *) m_sysContext);
}

// 必须绑定连接管理器并完成 System API 上下文的初始化
void ApplicationBasedOnTSSSystemAPI::bind(ConnectionManager& connectionManager)
{
    connectionManager.initializeSysContext(m_sysContext, m_sysContextSize);
}

// 解除绑定
void ApplicationBasedOnTSSSystemAPI::unbind()
{
    assert(m_sysContext);
    Tss2_Sys_Finalize(m_sysContext);
    memset(m_sysContext, 0x00, m_sysContextSize);
}

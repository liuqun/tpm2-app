/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <cstdio>
#include <cstdlib> // malloc()/free()
#include <cassert> // assert()
#include <sapi/tpm20.h>
#include "ConnectionManager.h"
#include "DBusConnectionManager.h"

/* 排版格式: 以下代码均使用4个空格缩进，不使用Tab缩进 */

#define MINIMUM_TCTI_CONTEXT_SIZE sizeof(TSS2_TCTI_CONTEXT_COMMON_CURRENT)

/// @function TSS2_RC InitDBusTcti(void *tcti_ctx, size_t *size);
/// 
/// @return TSS2_RC
#define InitDBusTcti(tcti_ctx, size) ((TSS2_RC) TSS2_TCTI_RC_NOT_IMPLEMENTED)

#ifdef TCTI_TABRMD_ENABLED
#include <tcti/tcti-tabrmd.h>
#undef InitDBusTcti
static TSS2_RC InitDBusTcti(TSS2_TCTI_CONTEXT *tcti_ctx, size_t size)
{
    tss2_tcti_tabrmd_init(tcti_ctx, size);
}
#endif

// 查询创建 TSS2_TCTI_CONTEXT 结构体需分配内存字节数
static size_t GetContextSize()
{
    size_t size;
    TSS2_RC err;

    size = 0;
    err = InitDBusTcti(NULL, &size);
    if (err) {
        fprintf(stderr, "Error: Failed to fetch size of TSS2_TCTI_CONTEXT from libtcti-tabrmd.so\n");
        abort(); // FIXME: throw/raise an expection to the up level
        return 0;
    }
    return size;
}

// 构造函数 DBusConnectionManager()
DBusConnectionManager::DBusConnectionManager()
{
    m_tctiContextSize = GetContextSize();
    if (m_tctiContextSize < MINIMUM_TCTI_CONTEXT_SIZE) {
        m_tctiContextSize = MINIMUM_TCTI_CONTEXT_SIZE;
    }
    m_tctiContext = (TSS2_TCTI_CONTEXT *) malloc(m_tctiContextSize);
    assert(m_tctiContext);
    if (!m_tctiContext) {
        fprintf(stderr, "Error: malloc() failed to allocate dynamic memory\n");
        exit (EXIT_FAILURE);
    }
    memset(m_tctiContext, 0x00, m_tctiContextSize);
}

// 析构函数
DBusConnectionManager::~DBusConnectionManager()
{
    /* 销毁 TCTI 上下文对象 */
    assert(m_tctiContext);
    free(m_tctiContext);
}

// 接口函数 connect()
void DBusConnectionManager::connect()
{
    TSS2_RC tctiError;

    tctiError = InitDBusTcti(m_tctiContext, &m_tctiContextSize);
    if (tctiError) {
        fprintf(stderr, "Error: tss2_tcti_tabrmd_init() returns 0x%X\n", (int) tctiError);
        abort(); // FIXME: throw/raise an expection to the up level
    }
}

// 接口函数 disconnect()
void DBusConnectionManager::disconnect()
{
    assert(m_tctiContext);
    TSS2_TCTI_CONTEXT_COMMON_CURRENT *ctx =
            (TSS2_TCTI_CONTEXT_COMMON_CURRENT *) m_tctiContext;
    if (!(ctx->finalize)) {
        return;
    }
    else if (ctx->version < 1) {
        return;
    }
    ctx->finalize(m_tctiContext);
    memset(m_tctiContext, 0x00, m_tctiContextSize);
}

/// 取出指向TCTI上下文区域的指针
void DBusConnectionManager::initializeSysContext(TSS2_SYS_CONTEXT *sysContext, size_t contextSize)
{
    TSS2_ABI_VERSION abiVersion;
    abiVersion.tssCreator = TSSWG_INTEROP;
    abiVersion.tssFamily = TSS_SAPI_FIRST_FAMILY;
    abiVersion.tssLevel = TSS_SAPI_FIRST_LEVEL;
    abiVersion.tssVersion = TSS_SAPI_FIRST_VERSION;

    TSS2_RC err = 0;
    err = Tss2_Sys_Initialize(
            sysContext,
            contextSize,
            m_tctiContext,
            &abiVersion);
    if (err) {
        fprintf(stderr, "Error: Tss2_Sys_Initialize() returns 0x%X\n", (int) err);
        abort(); // FIXME: throw/raise an expection to the up level
    }
}

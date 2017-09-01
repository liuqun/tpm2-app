/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <cstdio>
#include <cstdlib> // malloc()/free()
#include <cassert> // assert()
#include <stdexcept>
using std::exception;
#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include "ConnectionManager.h"
#include "SocketConnectionManager.h"

/* 排版格式: 以下代码均使用4个空格缩进，不使用Tab缩进 */

// 查询创建 TSS2_TCTI_CONTEXT 结构体需分配内存字节数
static size_t GetSocketTctiContextSize()
{
    TCTI_SOCKET_CONF emptyConf;
    size_t size;
    TSS2_RC err;

    err = InitSocketTcti(NULL, &size, &emptyConf, 0);
    if (err) {
        fprintf(stderr, "Error: Failed to fetch size of TSS2_TCTI_CONTEXT from libtcti-socket\n");
        fprintf(stderr, "(This error should NEVER happen)\n");
        return 0;
    }
    return size;
}

// 构造函数 SocketConnectionManager(szHostname, nPort)
SocketConnectionManager::SocketConnectionManager(const char *szHostname, uint16_t nPort)
{
    m_tctiContextSize = GetSocketTctiContextSize();
    m_tctiContext = (TSS2_TCTI_CONTEXT *) malloc(m_tctiContextSize);
    assert(m_tctiContext);
    if (!m_tctiContext) {
        fprintf(stderr, "Error: malloc() failed to allocate dynamic memory\n");
        exit (EXIT_FAILURE);
    }
    memset(m_tctiContext, 0x00, m_tctiContextSize);

    if (!szHostname) {
        szHostname = "127.0.0.1";
    }
    m_szHostname = szHostname;
    m_nPort = nPort;
}

// 析构函数
SocketConnectionManager::~SocketConnectionManager()
{
    /* 销毁 TCTI 上下文对象 */
    assert(m_tctiContext);
    free(m_tctiContext);
}

// 接口函数 connect()
void SocketConnectionManager::connect()
{
    TCTI_SOCKET_CONF conf;
    conf.hostname = (const char *) m_szHostname;
    conf.port = m_nPort;
    conf.logCallback = NULL;
    conf.logBufferCallback = NULL;
    conf.logData = NULL;

    TSS2_RC tctiError;
    tctiError = InitSocketTcti(m_tctiContext, &m_tctiContextSize, &conf, 0);
    if (tctiError) {
        fprintf(stderr, "Error: InitSocketTcti() returns 0x%X\n", (int) tctiError);
        // TODO: throw/raise an expection to the up level
    }
}

// 接口函数 disconnect()
void SocketConnectionManager::disconnect()
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
void SocketConnectionManager::initializeSysContext(TSS2_SYS_CONTEXT *sysContext, size_t contextSize)
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
        // TODO: throw/raise an expection to the up level
    }
}

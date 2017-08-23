/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <cstdio>
#include <cstdlib> // malloc()/free()
#include <cassert> // assert()
#include <stdexcept>
using std::exception;
#include <sapi/tpm20.h>
#include "TPMCommand.h"
#include "Client.h"

/* 排版格式: 以下函数均使用4个空格缩进，不使用Tab缩进 */

Client::Client() {
    m_sysContextSize = Tss2_Sys_GetContextSize(0);
    m_sysContext = (TSS2_SYS_CONTEXT *) malloc(m_sysContextSize);
    if (!m_sysContext)
    {
        fprintf(stderr, "Error: malloc() failed to allocate dynamic memory\n");
        exit (EXIT_FAILURE);
    }
    memset(m_sysContext, 0x00, m_sysContextSize);
    m_pLastCommand = NULL;
}

Client::~Client() {
    /* 销毁 System API 上下文对象 */
    assert(m_sysContext);
    Tss2_Sys_Finalize(m_sysContext);
    memset(m_sysContext, 0xFF, m_sysContextSize);
    free(m_sysContext);
}

void Client::initialize(TSSContextInitializer& initializer) {
    initializer.setupSysContext(m_sysContext, m_sysContextSize);
}

void Client::sendCommandAndWaitUntilResponseIsFetched(TPMCommand& cmd) {
    int timeout = TSS2_TCTI_TIMEOUT_BLOCK;
    try {
        sendCommand(cmd);
        m_pLastCommand = &cmd;
        fetchResponse(timeout);
    } catch (std::exception e) {
        // TODO: 处理发送命令桢或接收响应桢中可能遇到的异常情况, 例如响应超时等
    }
}

void Client::sendCommand(TPMCommand& cmd) {
    cmd.buildCmdPacket(m_sysContext); // 调用相应的 TSS 软件栈 Tss2_Sys_XXXX_Prepare() 函数

    // 异步发送命令帧
    TSS2_RC err = Tss2_Sys_ExecuteAsync(m_sysContext);
    if (err) {
        fprintf(stderr, "Error: Cannot send command packet: Tss2_Sys_ExecuteAsync() returns 0x%X\n", (int) err);
        // TODO: throw/raise an expection to the up level
    }
    m_pLastCommand = &cmd;
}

void Client::fetchResponse(int32_t timeout) {
    if (!m_pLastCommand) {
        fprintf(stderr, "Error: No response packet to fetch\n");
        // Note: throw/raise an expection to the up level
        const TSS2_RC AppError=(TSS2_APP_ERROR_LEVEL|TSS2_BASE_RC_BAD_SEQUENCE);
        throw AppError;
    }

    if (timeout < 0) {
        timeout = TSS2_TCTI_TIMEOUT_BLOCK;
    }
    TSS2_RC err = Tss2_Sys_ExecuteFinish(m_sysContext, timeout);
    if (err) {
        fprintf(stderr, "Error: Cannot fetch response packet: Tss2_Sys_ExecuteFinish() returns err = 0x%X\n", err);
        // TODO: throw/raise an expection to the up level
        throw err;
    }
    m_pLastCommand->unpackRspPacket(m_sysContext); // 调用相应的 TSS 软件栈 Tss2_Sys_XXXX_Complete() 函数
}

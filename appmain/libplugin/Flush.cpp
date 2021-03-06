﻿/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

#include <cstdio>
#include <stdexcept>
using std::invalid_argument;

// ============================================================================
// 自定义输入输出参数格式
// ============================================================================

/// 私有结构体
typedef struct In {
    TPMI_DH_CONTEXT flushHandle;
} Flush_In;

// ============================================================================
// 构造函数
// ============================================================================
FlushAuthSession::FlushAuthSession() {
    m_in = new Flush_In;
    m_out = NULL;
    m_cmdAuthsCount = 0;
}

// ============================================================================
// 析构函数
// ============================================================================
FlushAuthSession::~FlushAuthSession() {
    delete m_in;
}

// ============================================================================
// 配置要清除的授权会话
// ============================================================================
void FlushAuthSession::configSessionHandleToFlushAway(TPMI_SH_AUTH_SESSION sessionHandle) {
    // 首先应检查句柄类型, 会话句柄sessionHandle的高八位必须以0x02或0x03开始
    const UINT8 ht ///< handle type
            = (UINT8) (sessionHandle >> HR_SHIFT);
    if (ht < TPM_HT_HMAC_SESSION || ht > TPM_HT_POLICY_SESSION) {
        char msg[256];
        const size_t MaxLen = sizeof(msg);
        snprintf(msg, MaxLen, "Invalid session handle 0x%X (Handle type 0x%02X is not a session)", sessionHandle, ht);
        throw std::invalid_argument(msg);
    }
    m_in->flushHandle = (TPMI_DH_CONTEXT) sessionHandle;
}

// ============================================================================
// 组建命令帧报文
// ============================================================================
void FlushAuthSession::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 调用底层 API 填写输入参数
    Tss2_Sys_FlushContext_Prepare( // NOTE: 此处应检查函数返回值
            ctx, m_in->flushHandle);
}

// ============================================================================
// 构造函数
// ============================================================================
FlushLoadedKeyNode::FlushLoadedKeyNode() {
    m_in = new Flush_In;
    m_out = NULL;
}

// ============================================================================
// 析构函数
// ============================================================================
FlushLoadedKeyNode::~FlushLoadedKeyNode() {
    delete m_in;
}

// ============================================================================
// 配置要清除的密钥节点
// ============================================================================
void FlushLoadedKeyNode::configKeyNodeToFlushAway(TPM_HANDLE keyHandle) {
    // 首先应检查句柄类型, 密钥句柄keyHandle的高八位必须以0x80或0x81开始
    const UINT8 ht ///< handle type
            = (UINT8) (keyHandle >> HR_SHIFT);
    if (ht < TPM_HT_TRANSIENT || ht > TPM_HT_PERSISTENT) {
        char msg[256];
        const size_t MaxLen = sizeof(msg);
        snprintf(msg, MaxLen, "Invalid key handle 0x%X (Handle type 0x%02X is not a key)", keyHandle, ht);
        throw std::invalid_argument(msg);
    }
    m_in->flushHandle = (TPMI_DH_CONTEXT) keyHandle;
}

// ============================================================================
// 组建命令帧报文
// ============================================================================
void FlushLoadedKeyNode::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 调用底层 API 填写输入参数
    Tss2_Sys_FlushContext_Prepare( // NOTE: 此处应检查函数返回值
            ctx, m_in->flushHandle);
}

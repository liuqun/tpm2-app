/* encoding: utf-8 */
/// @file TPMCommand.cpp
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"

TPMCommand::TPMCommand() {
    m_in = NULL;
    m_out = NULL;

    // 命令帧携带的 AuthValue 个数
    m_cmdAuthsCount = 0; // 默认值

    TPMS_AUTH_COMMAND& cmdAuth = m_sendAuthValues[0];
    cmdAuth.sessionHandle = TPM_RS_PW; // 默认安全值
    cmdAuth.sessionAttributes.val = 0; // 默认清除所有标记位
    cmdAuth.nonce.t.size = 0;
    cmdAuth.hmac.t.size = 0;
}

void TPMCommand::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    TPMS_AUTH_COMMAND *cmdAuths[3];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;

    if (m_cmdAuthsCount >= 1) {
        cmdAuthsArray.cmdAuths = cmdAuths;
        cmdAuths[0] = cmdAuths[1] = cmdAuths[2] = NULL;
        cmdAuthsArray.cmdAuthsCount = 0;
        for (int i = 0; i < 3 && i < m_cmdAuthsCount; i++) {
            cmdAuthsArray.cmdAuthsCount++;
            cmdAuthsArray.cmdAuths[i] = &(m_sendAuthValues[i]);
        }
        Tss2_Sys_SetCmdAuths(ctx, &cmdAuthsArray);
    }
}

void TPMCommand::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    TPMS_AUTH_RESPONSE *rspAuths[3];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;

    rspAuthsArray.rspAuthsCount = 0;
    if (m_cmdAuthsCount >= 1) {
        rspAuthsArray.rspAuths = rspAuths;
        rspAuths[0] = rspAuths[1] = rspAuths[2] = NULL;
        rspAuthsArray.rspAuthsCount = 0;
        for (int i = 0; i < 3 && i < m_cmdAuthsCount; i++) {
            rspAuthsArray.rspAuthsCount++;
            rspAuthsArray.rspAuths[i] = &(m_fetchAuthResponse[i]);
        }
        Tss2_Sys_GetRspAuths(ctx, &rspAuthsArray);
        m_rspAuthsCount = rspAuthsArray.rspAuthsCount;
    }
}

TPMCommand::~TPMCommand() {
}

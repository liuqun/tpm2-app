/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include "KeyUtilities.h"
#include <sapi/tpm20.h>

KeyPublicDataReadingOperation::KeyPublicDataReadingOperation() {
    keyHandle = (TPM_HANDLE) 0;
    // 输出结果初始化
    keyPublicData.t.size = 0;
    keyName.t.name[0] = '\0'; // Used for debugging
    qualifiedName.t.name[0] = '\0'; // Used for debugging
    rc = TPM_RC_SUCCESS;
}

KeyPublicDataReadingOperation::~KeyPublicDataReadingOperation() {
}

/**
 * 通过句柄指定访问的密钥节点, 同时保存相应的访问授权数据
 *
 * (参数列表及返回值详见头文件中的声明)
 */
TPMI_DH_OBJECT KeyPublicDataReadingOperation::setKeyHandle(TPMI_DH_OBJECT handle) {
    this->keyHandle = handle;
    return handle;
}

/**
 * 执行 TPM 命令
 */
void KeyPublicDataReadingOperation::execute(TSS2_SYS_CONTEXT *pSysContext) {
    /* 调用 TPM 命令 */
    keyName.t.size = sizeof(keyName) - sizeof(qualifiedName.t.size);
    qualifiedName.t.size = sizeof(qualifiedName) - sizeof(qualifiedName.t.size);
    rc =  Tss2_Sys_ReadPublic(
            pSysContext,
            keyHandle, // IN
            (TSS2_SYS_CMD_AUTHS *) NULL, // 读取公开数据不需要授权, 另外只有输出参数没有输入参数
            &keyPublicData, // OUT
            &keyName, // OUT
            &qualifiedName, // OUT
            (TSS2_SYS_RSP_AUTHS *) NULL // 回传输出参数时可选择是否加密传输, 但这里可以暂时不实现该选项
            );
    if (rc) {
        // fprintf(stderr, "Error: rc=0x%X\n", rc);
        throw (TSS2_RC) rc;
    }
    return;
}

/**
 *
 */
const TPM2B_NAME& KeyPublicDataReadingOperation::getKeyName() {
    return keyName;
}

// ============================================================================

KeyLoadingOperation::KeyLoadingOperation() {
    parentHandle = 0; // 初始化清零 parentHandle, 仅仅为了便于测试

    parentAuthSettings.sessionHandle = TPM_RS_PW;
    parentAuthSettings.nonce.t.size = 0;
    parentAuthSettings.sessionAttributes.val = 0;
    parentAuthSettings.hmac.t.size = 0;
    parentAuthSettings.hmac.t.buffer[0] = '\0'; // Used for debugging

    keyHandle = 0; // 初始化清零 keyHandle, 仅仅为了便于测试
    keyName.t.size = 0;

    // 清空错误码缓存
    rc = TPM_RC_SUCCESS;
}

KeyLoadingOperation::~KeyLoadingOperation() {
    clearSensitiveAuthValues();
}

TPMI_DH_OBJECT KeyLoadingOperation::setParentHandleWithAuthPassword(
        TPMI_DH_OBJECT parentHandle,
        const BYTE authValue[], // 句柄授权数据
        UINT16 size // 数据长度
        ) {
    parentAuthSettings.sessionHandle = TPM_RS_PW;
    parentAuthSettings.nonce.t.size = 0;
    parentAuthSettings.sessionAttributes.val = 0;
    if (size > sizeof(parentAuthSettings.hmac.t.buffer)) {
        size = sizeof(parentAuthSettings.hmac.t.buffer); // 舍弃过长的字符, 防止溢出
    }
    parentAuthSettings.hmac.t.size = size;
    memcpy((void *) parentAuthSettings.hmac.t.buffer, (void *) authValue, size);
    this->parentHandle = parentHandle;
    return parentHandle;
}

void KeyLoadingOperation::clearSensitiveAuthValues() {
    memset(&(parentAuthSettings.hmac), 0x00, sizeof(parentAuthSettings.hmac));
}

TPMI_DH_OBJECT KeyLoadingOperation::setParentHandleWithoutAuthValue(TPMI_DH_OBJECT parentHandle) {
    this->parentHandle = parentHandle;
    return parentHandle;
}

void KeyLoadingOperation::loadExistingKey(TSS2_SYS_CONTEXT *pSysContext, const TPM2B_PRIVATE& keyPrivate, const TPM2B_PUBLIC& keyPublic) {
    TPMS_AUTH_COMMAND *cmdAuths[3];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;
    cmdAuths[0] = &parentAuthSettings;
    cmdAuthsArray.cmdAuthsCount = 1;
    cmdAuthsArray.cmdAuths = cmdAuths;

    TPMS_AUTH_RESPONSE *rspAuths[3];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;
    rspAuths[0] = &(m_sessionDataOut[0]);
    rspAuthsArray.rspAuthsCount = cmdAuthsArray.cmdAuthsCount;
    rspAuthsArray.rspAuths = rspAuths;

    // 调用API函数前, 需将输出数据区的size标志复位到最大值
    // 避免API返回错误编码TSS2_SYS_RC_INSUFFICIENT_BUFFER
    keyName.t.size = sizeof(keyName) - sizeof(keyName.t.size);

    /* 以上准备就绪后方可调用API函数 */
    rc = Tss2_Sys_Load(
            pSysContext, //
            parentHandle, //
            &cmdAuthsArray, //
            (TPM2B_PRIVATE *)&keyPrivate, // IN
            (TPM2B_PUBLIC *)&keyPublic, // IN
            // 以上为输入参数
            // 以下为输出参数
            &keyHandle, //
            &keyName, //
            &rspAuthsArray //
            );
    if (rc) {
        // fprintf(stderr, "Error: rc=0x%X\n", rc);
        throw (TSS2_RC) rc;
    }
    return;
}

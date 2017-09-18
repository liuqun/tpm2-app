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

void KeyLoadingOperation::loadExistingKey(TSS2_SYS_CONTEXT *pSysContext, const TPM2B_PRIVATE& inPrivate, const TPM2B_PUBLIC& inPublic) {
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
            (TPM2B_PRIVATE *)&inPrivate, // IN
            (TPM2B_PUBLIC *)&inPublic, // IN
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

// ============================================================================

/**
 * 构造函数
 *
 * 初始化填写成员变量初始默认值
 */
HMACKeyCreationOperation::HMACKeyCreationOperation() {
    parentHandle = 0; // 初始化清零 parentHandle, 仅仅为了便于测试

    m_cmdAuthsCount = 1;
    m_rspAuthsCount = 0;

    parentAuthSettings.sessionHandle = TPM_RS_PW;
    parentAuthSettings.nonce.t.size = 0;
    parentAuthSettings.sessionAttributes.val = 0;
    parentAuthSettings.hmac.t.size = 0;
    parentAuthSettings.hmac.t.buffer[0] = '\0'; // Used for debugging

    inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    inPublic.t.publicArea.nameAlg = TPM_ALG_NULL; // TPM 密钥树计算节点名称时使用的哈希算法, 初始值可以不设
    inPublic.t.publicArea.objectAttributes.val = (UINT32) 0; // 先清空全部标记位, 然后逐个设置
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1; // 访问密钥须提供用户授权信息
    inPublic.t.publicArea.objectAttributes.restricted = 1; // 被限定
    inPublic.t.publicArea.objectAttributes.decrypt = 0;
    inPublic.t.publicArea.objectAttributes.sign = 1; // 用于签名
    inPublic.t.publicArea.authPolicy.t.size = 0;
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC; // 必填项
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_NULL;
    inPublic.t.publicArea.unique.keyedHash.t.size = 0;
    inPublic.t.publicArea.unique.keyedHash.t.buffer[0] = '\0'; // 填零便于测试

    inPublic.t.size = 0; // 备忘: 作为Tss2_Sys_Create()函数的输入参数时, 该size字段实际上是无用的, 无需手动赋值, 因为Tss2_Sys_Create函数内部会自动计算TPM2B_PUBLIC数据块Marshal之后的长度

    // 其他输入参数的初始值
    outsideInfo.t.size = 0;
    creationPCR.count = 0;

    // 清空错误码缓存
    rc = TPM_RC_SUCCESS;
}

/**
 * 析构函数
 *
 * 清除成员变量中残留的授权数据/密码数据
 */
HMACKeyCreationOperation::~HMACKeyCreationOperation() {
    clearSensitiveParameters();
    clearSensitiveAuthValues();
}

/**
 * set Parent Handle with Auth Password
 */
TPMI_DH_OBJECT HMACKeyCreationOperation::setParentHandleWithAuthPassword(
        TPMI_DH_OBJECT parentHandle, /** 父句柄 */
        const BYTE authValue[], /** 句柄授权数据 */
        UINT16 size /** 数据长度 */
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
void HMACKeyCreationOperation::clearSensitiveAuthValues() {
    memset(&(parentAuthSettings.hmac), 0x00, sizeof(parentAuthSettings.hmac));
}
TPMI_DH_OBJECT HMACKeyCreationOperation::setParentHandleWithoutAuthValue(TPMI_DH_OBJECT parentHandle) {
    this->parentHandle = parentHandle;
    return parentHandle;
}

/**
 * 指定密码和额外的敏感数据
 *
 * (参数和返回值的具体定义见类成员函数声明)
 */
const TPM2B_SENSITIVE_CREATE& HMACKeyCreationOperation::setSensitiveParameters(
            const BYTE keyAuthValue[],
            UINT16 size,
            const BYTE extraSensitiveData[],
            UINT16 extraDataSize // 附加敏感数据, 长度可以为空
            ) {
    inSensitive.t.size = 0;
    const UINT16 MAX_AUTH_BUFSIZ = sizeof(inSensitive.t.sensitive.userAuth.t.buffer);
    if (size > MAX_AUTH_BUFSIZ) {
        size = MAX_AUTH_BUFSIZ;
    }
    inSensitive.t.sensitive.userAuth.t.size = size;
    if (size > 0)
    {
        memcpy(inSensitive.t.sensitive.userAuth.t.buffer, keyAuthValue, size);
        inSensitive.t.size += sizeof(inSensitive.t.sensitive.userAuth.t.size) + inSensitive.t.sensitive.userAuth.t.size;
    }
    const UINT16 MAX_EXTRA_SENSITIVE_DATA_BUFSIZ = sizeof(inSensitive.t.sensitive.data.t.buffer);
    if (extraDataSize > MAX_EXTRA_SENSITIVE_DATA_BUFSIZ) {
        extraDataSize = MAX_EXTRA_SENSITIVE_DATA_BUFSIZ;
    }
    inSensitive.t.sensitive.data.t.size = extraDataSize;
    if (extraDataSize > 0)
    {
        inSensitive.t.size += sizeof(UINT16) + inSensitive.t.sensitive.data.t.size;
    }
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1; // 确保创建密钥时正确的标志位被设置
    return inSensitive;
}
void HMACKeyCreationOperation::clearSensitiveParameters() {
    memset(&inSensitive, 0x00, sizeof(inSensitive));
}

/**
 * 选择一种哈希算法
 *
 * (参数和返回值的具体定义见类成员函数声明)
 */
TPMI_ALG_HASH HMACKeyCreationOperation::setHashAlgorithm(TPMI_ALG_HASH hashAlg) {
    void *p;
    p = &(inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details);
    memcpy(p, &hashAlg, sizeof(TPMI_ALG_HASH));
    return hashAlg;
}

/**
 * 指定密钥树节点名称运算采用哪种哈希算法
 * 注意这里不是指定HMAC运算所要采用的哈希算法
 *
 * (参数和返回值的具体定义见类成员函数声明)
 */
TPMI_ALG_HASH HMACKeyCreationOperation::setKeyNameHashAlgorithm(TPMI_ALG_HASH keyNameHashAlg) {
    inPublic.t.publicArea.nameAlg = keyNameHashAlg;
    return keyNameHashAlg;
}

/**
 * 创建密钥
 *
 * (参数的具体定义见类成员函数声明)
 */
void HMACKeyCreationOperation::createKey(TSS2_SYS_CONTEXT *pSysContext) {
    outPrivate.t.size = sizeof(TPM2B_PRIVATE) - sizeof(UINT16);
    outPublic.t.size = 0; // 必须被初始化为 0, 否则报错 0x8000B: TSS2_SYS_RC_BAD_VALUE
    creationData.t.size = 0; // 必须被初始化为 0, 否则报错 0x8000B: TSS2_SYS_RC_BAD_VALUE
    creationHash.t.size = sizeof(TPM2B_DIGEST) - sizeof(UINT16);
    creationTicket.tag = 0;
    creationTicket.hierarchy = 0x0;
    creationTicket.digest.t.size = sizeof(TPM2B_DIGEST) - sizeof(UINT16);

    TPMS_AUTH_COMMAND *cmdAuths[3];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;
    int i;
    i = 0;
    cmdAuths[i++] = &parentAuthSettings;
    if (m_cmdAuthsCount >= 2) {
        cmdAuths[i++] = &sensitiveParameterProtectionAuthSettings;
    }
    m_cmdAuthsCount = i;
    cmdAuthsArray.cmdAuthsCount = m_cmdAuthsCount;
    cmdAuthsArray.cmdAuths = cmdAuths;

    TPMS_AUTH_RESPONSE *rspAuths[3];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;
    rspAuths[0] = &(m_sessionDataOut[0]);
    rspAuths[1] = &(m_sessionDataOut[1]);
    rspAuths[2] = &(m_sessionDataOut[2]);
    rspAuthsArray.rspAuthsCount = m_cmdAuthsCount;
    rspAuthsArray.rspAuths = rspAuths;

    /* 调用 TPM 命令 */
    rc = Tss2_Sys_Create(
            pSysContext, //
            parentHandle, //
            &cmdAuthsArray, //
            &inSensitive, //
            &inPublic, //
            &outsideInfo, //
            &creationPCR, //
            // 以上为输入参数
            // 以下为输出参数
            &outPrivate, // 1
            &outPublic, // 2
            &creationData, // 3
            &creationHash, // 4
            &creationTicket, // 5
            &rspAuthsArray // 6
            );
    if (rc) {
        // fprintf(stderr, "Error: rc=0x%X\n", rc);
        throw (TSS2_RC) rc;
    }
    m_rspAuthsCount = rspAuthsArray.rspAuthsCount;
    return;
}

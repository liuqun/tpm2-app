/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <sstream>
using std::stringstream;
#include <stdexcept>
using std::runtime_error;
#include <sapi/tpm20.h>
#include "Client.h"
#include "TPMCommand.h"

/* 排版格式: 以下函数均使用4个空格缩进，不使用Tab缩进 */

/// 是否开启printf调试信息
#define ENABLE_DEBUG_PRINTF 0 ///< 可选值: 0表示禁用printf(); 1或任意非零值表示允许输出printf()调试信息.

#if ENABLE_DEBUG_PRINTF
#include <cstdio>
#warning // printf() has been enabled now. (To disable printf, you may set ENABLE_DEBUG_PRINTF to 0)
#endif

#if !ENABLE_DEBUG_PRINTF
inline static int NoPrintf()
{
    return (0);
}
// 通过函数名宏替换的方式注释掉所有printf语句
#undef printf
#define printf(...) NoPrintf()
#undef fprintf
#define fprintf(fp, ...) NoPrintf()
#endif

// (函数描述参见头文件中的定义)
TPM_HANDLE HMACSequenceScheduler::loadExternalKey(const void *key, unsigned int length) {
    TPMI_RH_HIERARCHY hierarchy = TPM_RH_NULL; // 在 TPM_RH_NULL 区域创建的节点是临时节点
    TPM_HANDLE result = 0xFC000000;
    TPMCommands::LoadExternal loadextn;
    try {
        printf("设置 LoadExternal 命令帧参数\n");
        loadextn.configHierarchy(hierarchy);
        loadextn.configSensitiveDataBits(key, length);
        loadextn.configKeyTypeKeyedHashKey();
        loadextn.configKeyAuthValue(m_externalKeyPassword, m_externalKeyPasswordLen);
        printf("发送 LoadExternal 命令桢创建临时节点(用于存储用户输入的自定义对称密钥)\n");
        sendCommand(loadextn);
        fetchResponse();
        printf("临时节点创建成功, 密钥句柄=0x%08X\n", (int)loadextn.outObjectHandle());
        result = loadextn.outObjectHandle();
    } catch (TSS2_RC rc) {
        std::stringstream msg;
        msg << "TPM Command LoadExternal() has returned an error code 0x" << std::hex << rc;
        throw std::runtime_error(msg.str());
    } catch (...) {
        throw std::runtime_error("Unknown error happened in TPM command LoadExternal()\n");
    }

    char buf[length];
    memset(buf, 0xFF, length);
    loadextn.configSensitiveDataBits(buf, length); // 手动覆盖清除之前缓存的对称密钥值副本(清除敏感数据)

    return result;
}

// (函数描述参见头文件中的定义)
HMACSequenceScheduler::HMACSequenceScheduler() {
    m_externalKeyPassword = (void *)"";
    m_externalKeyPasswordLen = strlen((char *)m_externalKeyPassword);
    m_savedSequenceHandle = 0x0;
    m_cachedData.t.size = 0;
    m_hmacDigest.t.size = 0;
    m_validationTicket.tag = 0;
}

// (函数描述参见头文件中的定义)
HMACSequenceScheduler::~HMACSequenceScheduler() {
    // 擦除缓存的明文数据
    memset(&m_cachedData, 0xFF, sizeof(m_cachedData));
}

// (函数描述参见头文件中的定义)
void HMACSequenceScheduler::start(TPM_HANDLE keyHandle, TPMI_ALG_HASH hashAlgorithm) {
    TPMS_AUTH_COMMAND *cmdAuths[3];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;
    TPMS_AUTH_COMMAND cmdAuthBlob;
    cmdAuthBlob.sessionHandle = TPM_RS_PW;
    cmdAuthBlob.nonce.t.size = 0;
    cmdAuthBlob.sessionAttributes.val = 0x0;
    cmdAuthBlob.hmac.t.size = 0; // FIXME: 未指定keyHandle密码
    cmdAuths[0] = &cmdAuthBlob;
    cmdAuths[1] = cmdAuths[2] = NULL;
    cmdAuthsArray.cmdAuths = cmdAuths;
    cmdAuthsArray.cmdAuthsCount = 1;

    TPMS_AUTH_RESPONSE *rspAuths[3];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;
    TPMS_AUTH_RESPONSE rspAuthBlob;
    memset(&rspAuthBlob, 0x00, sizeof(rspAuthBlob));
    rspAuths[0] = &rspAuthBlob;
    rspAuths[1] = rspAuths[2] = NULL;
    rspAuthsArray.rspAuths = rspAuths;
    rspAuthsArray.rspAuthsCount = cmdAuthsArray.cmdAuthsCount;

    TPM2B_AUTH& auth=m_savedAuthValueForSequenceHandle;
    auth.t.size = 0; // TODO: 允许自定义HMAC流密码

    TPMI_DH_OBJECT sequenceHandle = 0x0;

    if (TPM_ALG_NULL == hashAlgorithm) {
        // FIXME: Warning: 当调用者指定算法编码 algorithm=0x0010 (即 TPM_ALG_NULL) 时, TPM 会将该序列初始化成一个 EventSequence (事件序列)
    }

    m_savedSequenceHandle = 0x0; // 方便调试
    TPM_RC rc = Tss2_Sys_HMAC_Start(m_sysContext,
            keyHandle, // IN
            &cmdAuthsArray, // IN
            &auth, // IN
            hashAlgorithm, // IN
            &sequenceHandle, // OUT
            &rspAuthsArray /* OUT */);
    if (rc) {
        std::stringstream msg;
        msg << "HMACSequenceScheduler::start(): TPM Command Tss2_Sys_HMAC_Start() has returned an error code 0x" << std::hex << rc;
        throw runtime_error(msg.str());
    }
    m_savedSequenceHandle = sequenceHandle;
    m_cachedData.t.size = 0;
}

// (函数描述参见头文件中的定义)
void HMACSequenceScheduler::inputData(const void *data_, unsigned int length) {
    if (!m_savedSequenceHandle) {
        throw runtime_error("HMACSequenceScheduler::inputData(): 函数调用次序错误, 请先调用start()");
    }

    TPMS_AUTH_COMMAND *cmdAuths[3];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;
    TPMS_AUTH_COMMAND cmdAuthBlob;
    cmdAuthBlob.sessionHandle = TPM_RS_PW;
    cmdAuthBlob.nonce.t.size = 0;
    cmdAuthBlob.sessionAttributes.val = 0x0;
    cmdAuthBlob.hmac = m_savedAuthValueForSequenceHandle; // 密码
    cmdAuths[0] = &cmdAuthBlob;
    cmdAuths[1] = cmdAuths[2] = NULL;
    cmdAuthsArray.cmdAuths = cmdAuths;
    cmdAuthsArray.cmdAuthsCount = 1;


    TPMS_AUTH_RESPONSE *rspAuths[3];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;
    TPMS_AUTH_RESPONSE rspAuthBlob;
    memset(&rspAuthBlob, 0x00, sizeof(rspAuthBlob));
    rspAuths[0] = &rspAuthBlob;
    rspAuths[1] = rspAuths[2] = NULL;
    rspAuthsArray.rspAuths = rspAuths;
    rspAuthsArray.rspAuthsCount = cmdAuthsArray.cmdAuthsCount;

    const BYTE *data = (const BYTE *) data_;

    const size_t MaxBufferSize = sizeof(m_cachedData.t.buffer);
    const size_t leftBufferSize = MaxBufferSize - m_cachedData.t.size;

    size_t n;
    n = length;
    if (length > leftBufferSize) {
        n = leftBufferSize;
    }
    memcpy(m_cachedData.t.buffer+m_cachedData.t.size, data, n);
    m_cachedData.t.size += n;
    data += n;
    length -= n;
    if (m_cachedData.t.size < MaxBufferSize) {
        // 发现尚未凑满一个1024字节数据包, 所以此时不必发送任何数据
        return;
    }

    length = length + m_cachedData.t.size;
    while (length >= MaxBufferSize) { // 每轮发送1024字节
        TPM_RC err = 0;
        err = Tss2_Sys_SequenceUpdate(m_sysContext,
                m_savedSequenceHandle, // OUT
                &cmdAuthsArray, // IN
                &m_cachedData, // IN
                &rspAuthsArray /* OUT */);
        if (err) {
            std::stringstream msg;
            msg << "HMACSequenceScheduler::inputData(): TPM Command Tss2_Sys_SequenceUpdate() has returned an error code 0x" << std::hex << err;
            throw runtime_error(msg.str());
        }
        length -= MaxBufferSize;
        if (length >= MaxBufferSize) {
            memcpy(m_cachedData.t.buffer, data, MaxBufferSize);
            m_cachedData.t.size = MaxBufferSize;
            data += MaxBufferSize;
        }
    }
    if (length > 0) { // 缓存最后余留的数据(不足1024字节), 留待下轮凑满1024字节后再发送
        memcpy(m_cachedData.t.buffer, data, length);
    }
    m_cachedData.t.size = (UINT16) length; // 有时候恰好=0
}

// (函数描述参见头文件中的定义)
const TPM2B_DIGEST& HMACSequenceScheduler::outHMAC() {
    return m_hmacDigest;
}

// (函数描述参见头文件中的定义)
const TPMT_TK_HASHCHECK& HMACSequenceScheduler::outValidationTicket() {
    return m_validationTicket;
}

// (函数描述参见头文件中的定义)
void HMACSequenceScheduler::complete() {
    if (!m_savedSequenceHandle) {
        throw runtime_error("HMACSequenceScheduler::complete(): 函数调用次序错误, 请先调用start()");
    }

    TPMS_AUTH_COMMAND *cmdAuths[3];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;
    TPMS_AUTH_COMMAND cmdAuthBlob;
    cmdAuthBlob.sessionHandle = TPM_RS_PW;
    cmdAuthBlob.nonce.t.size = 0;
    cmdAuthBlob.sessionAttributes.val = 0x0;
    cmdAuthBlob.hmac = m_savedAuthValueForSequenceHandle; // 密码
    cmdAuths[0] = &cmdAuthBlob;
    cmdAuths[1] = cmdAuths[2] = NULL;
    cmdAuthsArray.cmdAuths = cmdAuths;
    cmdAuthsArray.cmdAuthsCount = 1;

    TPMS_AUTH_RESPONSE *rspAuths[3];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;
    TPMS_AUTH_RESPONSE rspAuthBlob;
    memset(&rspAuthBlob, 0x00, sizeof(rspAuthBlob));
    rspAuths[0] = &rspAuthBlob;
    rspAuths[1] = rspAuths[2] = NULL;
    rspAuthsArray.rspAuths = rspAuths;
    rspAuthsArray.rspAuthsCount = cmdAuthsArray.cmdAuthsCount;

    TPMI_RH_HIERARCHY hierarchy;
    hierarchy = TPM_RH_NULL; // TODO: 应该允许用户自定义修改validationTicket的hierarchy

    m_hmacDigest.t.size = sizeof(m_hmacDigest.t.buffer);

    TPM_RC err = 0;
    err = Tss2_Sys_SequenceComplete(m_sysContext,
            m_savedSequenceHandle, // IN
            &cmdAuthsArray, // IN
            &m_cachedData, // IN
            hierarchy, // IN
            &m_hmacDigest, // OUT
            &m_validationTicket, // OUT
            &rspAuthsArray); //
    if (err) {
        std::stringstream msg;
        msg << "HMACSequenceScheduler::complete(): TPM Command Tss2_Sys_SequenceComplete() has returned an error code 0x" << std::hex << err;
        throw runtime_error(msg.str());
    }
}

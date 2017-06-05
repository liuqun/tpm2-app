/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// ============================================================================
// 自定义输入输出参数格式
// ============================================================================

/// 私有结构体
typedef struct In {
    TPMI_DH_OBJECT tpmKey; ///< 用于解密 encryptedSalt 数据的句柄, 取值可以是 TPM_RH_NULL 或 TPM 密钥树已加载的密钥句柄, 并且要求已设置 decrypt=1 选项
    TPMI_DH_ENTITY bind; ///< 绑定任意句柄, 把访问该句柄时所需要的授权值作为新会话的授权值
    TPM2B_NONCE nonceCaller; ///< nonceTPM 与 nonceCaller 成对出现
    TPM2B_ENCRYPTED_SECRET encryptedSalt; ///< 保存一段密文数据, 用于为会话加盐. @note If tpmKey is TPM_RH_NULL, then encryptedSalt is required to be an empty buffer.
    TPM_SE sessionType; ///< 可选取值: TPM_SE_HMAC=0x00, TPM_SE_POLICY=0x01, 暂不支持 TPM_SE_TRIAL=0x03
    TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH authHash; ///< 可选值包括 TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TPM_ALG_SM3_256, 但不能被设置为 TPM_ALG_NULL
} StartAuthSession_In;

/// 私有结构体
typedef struct Out {
    TPMI_SH_AUTH_SESSION sessionHandle;
    TPM2B_NONCE nonceTPM; ///< nonceTPM 与 nonceCaller 成对出现
} StartAuthSession_Out;

// ============================================================================
// 构造函数
// ============================================================================
StartAuthSession::StartAuthSession() {
    m_in = new StartAuthSession_In;
    m_out = new StartAuthSession_Out;
    m_in->tpmKey = TPM_RH_NULL;
    m_in->bind = TPM_RH_NULL;
    m_in->encryptedSalt.t.size = 0;
    m_in->sessionType = (TPM_SE) TPM_SE_HMAC;
    m_in->symmetric.algorithm = TPM_ALG_NULL;
    m_in->symmetric.keyBits.sym = 0;
    m_in->symmetric.mode.sym = TPM_ALG_ERROR;
    m_in->authHash = TPM_ALG_SHA1;
    memset(m_out, 0x00, sizeof(*m_out));
    m_cmdAuthsCount = 0; // StartAuthSession 命令默认不使用授权块
}

// ============================================================================
// 析构函数
// ============================================================================
StartAuthSession::~StartAuthSession() {
    delete m_in;
    delete m_out;
}

// ============================================================================
// 设置要创建授权会话类型: HMAC 授权会话
// ============================================================================
void StartAuthSession::configSessionTypeAsHMACSession() {
    m_in->sessionType = TPM_SE_HMAC;
}

// ============================================================================
// 设置要创建授权会话类型: Policy 授权会话
// ============================================================================
void StartAuthSession::configSessionTypeAsPolicySession() {
    m_in->sessionType = TPM_SE_POLICY;
}

// ============================================================================
// 设置新会话加密选项:
// 设置 salt 值并指定 TPM 解读该 salt 值时所需使用的密钥句柄
// ============================================================================
void StartAuthSession::configEncryptedSaltAlongWithItsDecryptKey(UINT16 saltSize, void *encryptedSaltValue, TPM_HANDLE decryptKey) {
    m_in->tpmKey = decryptKey;
    if (saltSize > sizeof(m_in->encryptedSalt.t.secret)) {
        saltSize = sizeof(m_in->encryptedSalt.t.secret);
    }
    m_in->encryptedSalt.t.size = saltSize;
    memcpy(m_in->encryptedSalt.t.secret, encryptedSaltValue, saltSize);
}

// ============================================================================
// 设置新会话加密选项:
// 通过绑定某个 Entity 对象(密钥或 NV Index)为该会话指定的访问授权值, 即访问密码
// ============================================================================
void StartAuthSession::configBindEntity(TPM_HANDLE entityHandle) {
    m_in->bind = entityHandle;
}

// ============================================================================
// 设置新会话的第一个 nonce 值(即 nonceCaller)
// ============================================================================
void StartAuthSession::configNonceCaller(UINT16 nonceSize, void *nonceValue) {
    if (nonceSize > sizeof(m_in->nonceCaller.t.buffer)) {
        nonceSize = sizeof(m_in->nonceCaller.t.buffer);
    }
    m_in->encryptedSalt.t.size = nonceSize;
    memcpy(m_in->encryptedSalt.t.secret, nonceValue, nonceSize);
}

// ============================================================================
// 组建命令帧报文
// ============================================================================
void StartAuthSession::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_StartAuthSession_Prepare(// NOTE: 此处应检查函数返回值
            ctx,
            m_in->tpmKey,
            m_in->bind,
            &(m_in->nonceCaller),
            &(m_in->encryptedSalt),
            m_in->sessionType,
            &(m_in->symmetric),
            m_in->authHash
            );
    // 然后显式调用父类的成员函数完成填写 AuthValue 工作
    this->TPMCommand::buildCmdPacket(ctx);
}

// ============================================================================
// 解码应答桢报文
// ============================================================================
void StartAuthSession::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    m_rspAuthsCount = m_cmdAuthsCount;
    // 先显式调用父类的成员函数(通过该函数写入授权值)
    this->TPMCommand::unpackRspPacket(ctx);
    // 然后调用 API 函数进行解包
    m_out->nonceTPM.t.size = sizeof(m_out->nonceTPM) - sizeof(UINT16); // 必填
    Tss2_Sys_StartAuthSession_Complete(// NOTE: 此处应检查函数返回值
            ctx,
            &(m_out->sessionHandle),
            &(m_out->nonceTPM)
            );
}

// ============================================================================
// 输出创建的会话句柄
// ============================================================================
TPMI_SH_AUTH_SESSION StartAuthSession::outSessionHandle() {
    return m_out->sessionHandle;
}

// ============================================================================
// 输出 TPM 返回的 Nonce 随机数
// ============================================================================
const TPM2B_NONCE& StartAuthSession::outNonceTpm() {
    return m_out->nonceTPM;
}

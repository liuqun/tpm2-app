/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// ============================================================================
// 自定义输入输出参数格式
// ----------------------------------------------------------------------------

/// 私有结构体 HMAC_In
typedef struct In {
    TPMI_DH_OBJECT handle; ///< 指定要调用的 TPM 密钥句柄
    TPM2B_MAX_BUFFER buffer; ///< 用于缓存输入数据, 长度限制:不超过 MAX_DIGEST_BUFFER=1024 字节.
    TPMI_ALG_HASH hashAlg; ///< 哈希算法代号, 当前支持 5 种取值, 分别是: TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TPM_ALG_SM3_256.
} HMAC_In;

/// 私有结构体 HMAC_Out
typedef struct Out {
    TPM2B_DIGEST outHMAC; ///< 存储 TPM 输出的 HMAC 计算结果
} HMAC_Out;

// ============================================================================
// 构造函数
// ----------------------------------------------------------------------------
HMAC::HMAC() {
    m_in = new HMAC_In;
    m_out = new HMAC_Out;

    /* 因 HMAC 计算需调用密钥, 必须提供 auth value 用于访问密钥 */
    m_cmdAuthsCount = 1;
    TPMS_AUTH_COMMAND& cmdAuth = m_sendAuthValues[0];
    cmdAuth.sessionHandle = TPM_RS_PW; // 默认安全值
    cmdAuth.nonce.t.size = 0;
    cmdAuth.sessionAttributes.val = 0; // 先清空所有标记位
    cmdAuth.sessionAttributes.continueSession = 1;
    cmdAuth.hmac.t.size = 0;

    /* 密钥句柄默认值 */
    m_in->handle = 0x80000001; // FIXME: 该默认值不一定合适

    /* 初始化输入缓冲区, 并设置默认值 */
    m_in->buffer.t.size = 0;
    m_in->hashAlg = TPM_ALG_SHA1;

    /* 清空输出缓冲区 */
    memset(m_out, 0x00, sizeof(*m_out));
}

// ============================================================================
// 析构函数
// ----------------------------------------------------------------------------
HMAC::~HMAC() {
    delete m_in;
    delete m_out;
    eraseCachedAuthPassword(); // 将已缓存的 auth value 擦除以免密码泄露
}

// ============================================================================
// 指定要使用哈希算法为 SHA1
// ----------------------------------------------------------------------------
void HMAC::configUsingHashAlgorithmSHA1() {
    m_in->hashAlg = TPM_ALG_SHA1;
}

// ============================================================================
// 指定要使用哈希算法为 SHA256
// ----------------------------------------------------------------------------
void HMAC::configUsingHashAlgorithmSHA256() {
    m_in->hashAlg = TPM_ALG_SHA256;
}

// ============================================================================
// 指定要使用哈希算法为 SHA384
// ----------------------------------------------------------------------------
void HMAC::configUsingHashAlgorithmSHA384() {
    m_in->hashAlg = TPM_ALG_SHA384;
}

// ============================================================================
// 指定输入数据
// ----------------------------------------------------------------------------
void HMAC::configInputData(const void *data, UINT16 length) {
    if (length > sizeof(m_in->buffer.t.buffer)) {
        length = sizeof(m_in->buffer.t.buffer); // 直接截断超出长度限制的字节. 这里暂不输出错误或警告信息!
    }
    m_in->buffer.t.size = length;
    memcpy(m_in->buffer.t.buffer, data, length);
}

// ============================================================================
// 擦除已缓存的输入数据
// ----------------------------------------------------------------------------
void HMAC::eraseCachedInputData() {
    memset(m_in->buffer.t.buffer, 0x00, sizeof(m_in->buffer.t.buffer));
    m_in->buffer.t.size = 0;
}
/**
 * 指定 HMAC 使用的密钥
 */
void HMAC::configHMACKey(TPM_HANDLE keyHandle){
    m_in->handle = (TPMI_DH_OBJECT) keyHandle;
}

// ============================================================================
// 指定访问授权方式(通过哪种会话进行授权校验)
// ----------------------------------------------------------------------------
void HMAC::configAuthSession(
        TPMI_SH_AUTH_SESSION authSessionHandle ///< 会话句柄, 可选取值包括: 明文密码授权会话句柄 TPM_RS_PW 或其他 HMAC/Policy 会话句柄
        ) {
    m_sendAuthValues[0].sessionHandle = authSessionHandle;
}

// ============================================================================
// 指定授权值访问密码(属于敏感数据)
// ----------------------------------------------------------------------------
void HMAC::configAuthPassword(const void *password, UINT16 length) {
    // 调用父类的成员函数完成设置密码的具体工作
    TPMCommand::configAuthPassword(password, length);
}

// ============================================================================
// 擦除临时缓存的授权值
// ----------------------------------------------------------------------------
void HMAC::eraseCachedAuthPassword() {
    // 调用父类的成员函数擦除密码
    TPMCommand::eraseCachedAuthPassword();
}

// ============================================================================
// 组建命令帧报文
// ----------------------------------------------------------------------------
void HMAC::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_HMAC_Prepare( // NOTE: 此处应检查函数返回值
            ctx, // API 上下文
            m_in->handle, // 指定 HMAC 密钥句柄
            &(m_in->buffer), // 输入数据
            m_in->hashAlg // 指定算法
            );
    // 然后调用父类的成员函数(注: HMAC 命令本身无需授权, 预留此接口仅用于HMAC校验或参数加解密)
    TPMCommand::buildCmdPacket(ctx);
}

// ============================================================================
// 解码应答桢报文
// ----------------------------------------------------------------------------
void HMAC::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用父类的成员函数(注: HMAC 命令本身无需授权, 预留此接口仅用于HMAC校验或参数加解密)
    TPMCommand::unpackRspPacket(ctx);
    // 然后调用 API 函数进行解包
    m_out->outHMAC.t.size = sizeof(m_out->outHMAC.t.buffer);// 此处填写最大值可以避免 Tss2_Sys_HMAC_Complete() 函数返回错误码 TSS2_SYS_RC_INSUFFICIENT_BUFFER
    Tss2_Sys_HMAC_Complete( // NOTE: 此处应检查函数返回值
            ctx, // API 上下文
            &(m_out->outHMAC) // 输出摘要
            );
}

// ============================================================================
// 输出哈希计算的结果, 即摘要值
// ----------------------------------------------------------------------------
const TPM2B_DIGEST& HMAC::outHMAC() {
    return m_out->outHMAC;
}

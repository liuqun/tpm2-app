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
    TPMI_DH_OBJECT keyHandle; ///< Handle of key that will perform signing.
    TPM2B_DIGEST digest; ///< Digest to be signed.
    TPMT_SIG_SCHEME inScheme;
    TPMT_TK_HASHCHECK validation; ///< 哈希摘要的 ticket (通常来自 TPMCommands::Hash 命令的输出)
} Sign_In;

/// 私有结构体
typedef struct Out {
    TPMT_SIGNATURE signature;
} Sign_Out;

// ============================================================================
// 构造函数
// ----------------------------------------------------------------------------
Sign::Sign() {
    m_in = new Sign_In;
    m_out = new Sign_Out;

    /* 初始化输入缓冲区, 并设置默认值 */
    m_cmdAuthsCount = 1; // 需授权访问 keyHandle
    m_in->keyHandle = 0x80FFFFFF; // 随意设置一个无效的初始值, 便于调试程序
    m_in->digest.t.size = 0;
    m_in->inScheme.scheme = TPM_ALG_RSASSA;
    m_in->inScheme.details.rsassa.hashAlg = TPM_ALG_SHA1;
    m_in->validation.tag = 0x8024; /// @see TPM_ST_HASHCHECK
    m_in->validation.hierarchy = TPM_RH_NULL;
    m_in->validation.digest.t.size = 0;

    /* 清空输出缓冲区 */
    memset(m_out, 0x00, sizeof(*m_out));
}

// ============================================================================
// 析构函数
// ----------------------------------------------------------------------------
Sign::~Sign() {
    eraseCachedAuthPassword();
    delete m_in;
    delete m_out;
}

// ============================================================================
// 指定访问签名密钥授权方式(通过哪种会话进行授权校验)
// ----------------------------------------------------------------------------
void Sign::configAuthSession(TPMI_SH_AUTH_SESSION authSessionHandle) {
    m_sendAuthValues[0].sessionHandle = authSessionHandle;
}

// ============================================================================
// 指定授权值访问密码(属于敏感数据)
// ----------------------------------------------------------------------------
void Sign::configAuthPassword(const void *password, UINT16 length) {
    // 调用父类的成员函数完成设置密码的具体工作
    TPMCommand::configAuthPassword(password, length);
}

// ============================================================================
// 擦除临时缓存的授权值
// ----------------------------------------------------------------------------
void Sign::eraseCachedAuthPassword() {
    // 调用父类的成员函数擦除密码
    TPMCommand::eraseCachedAuthPassword();
}

// ============================================================================
// 指定数字签名操作要使用的签名密钥(不对称密钥, 可选取 RSA, ECC 等类型)
// ----------------------------------------------------------------------------
void Sign::configSigningKey(TPM_HANDLE keyHandle) {
    m_in->keyHandle = keyHandle; // 此处暂时没有对密钥句柄的高八位进行检查, 高八位应该以0x80或0x81开头
}

// ============================================================================
// 输入待签名的哈希摘要
// ----------------------------------------------------------------------------
void Sign::configDigestToBeSigned(const void *digestData, UINT16 digestLength) {
    if (digestLength > sizeof(m_in->digest.t.buffer)) {
        digestLength = sizeof(m_in->digest.t.buffer); // 直接截断超出长度限制的字节. 这里暂不输出错误或警告信息!
    }
    m_in->digest.t.size = digestLength;
    memcpy(m_in->digest.t.buffer, digestData, digestLength); // 我们推荐: 不检查输入参数 digestData 指针是否为空指针, 而由调用者自己对指针的有效性进行负责; 同时我们的模块返回值也坚决避免去输出空指针表示错误给调用者.
}

// ============================================================================
// 提供一份证明用于确认该哈希摘要是之前由 TPM 输出的
// ----------------------------------------------------------------------------
void Sign::configValidationTicket(const TPMT_TK_HASHCHECK& ticket) {
    m_in->validation = ticket;
}

// ============================================================================
// 组建命令帧报文
// ----------------------------------------------------------------------------
void Sign::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_Sign_Prepare( // NOTE: 此处应检查函数返回值
            ctx, // TSS2_SYS_CONTEXT *sysContext 上下文
            m_in->keyHandle, // 指定算法
            &(m_in->digest), // 输入待签名的哈希摘要
            &(m_in->inScheme), // 若 keyHandle 缺少 scheme
            &(m_in->validation) // 输入哈希摘要的 ticket (通常来自 TPMCommands::Hash 命令的输出)
            );
    // 然后显式调用父类的成员函数
    TPMCommand::buildCmdPacket(ctx);
}

// ============================================================================
// 解码应答桢报文
// ----------------------------------------------------------------------------
void Sign::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先显式调用父类的成员函数
    TPMCommand::unpackRspPacket(ctx);
    // 然后调用 API 函数进行解包
    Tss2_Sys_Sign_Complete( // NOTE: 此处应检查函数返回值
            ctx, // TSS2_SYS_CONTEXT *sysContext 上下文
            &(m_out->signature) // 输出数字签名
            );
}

// ============================================================================
// 输出数字签名计算结果
// ----------------------------------------------------------------------------
const TPMT_SIGNATURE& Sign::outSignature() {
    return m_out->signature;
}

// ============================================================================
// 配置 Scheme
// ----------------------------------------------------------------------------
void Sign::configScheme(const TPMT_SIG_SCHEME& inScheme ///< 头文件 TPMCommand.h 中指定了一个默认值=TPMCommands::Sign::DefaultSigningScheme
            ) {
    switch(inScheme.scheme) {
        case TPM_ALG_ECDAA:
            m_in->inScheme.details.ecdaa.count = inScheme.details.ecdaa.count; ///< @note 只有 TPMS_SCHEME_ECDAA 结构体额外附加一个 2 字节的 count 字段, 故进行单独处理
            /* [[fallthrough]]; */
        case TPM_ALG_RSASSA:
        case TPM_ALG_RSAPSS:
        case TPM_ALG_ECDSA:
        case TPM_ALG_SM2:
        case TPM_ALG_ECSCHNORR:
        case TPM_ALG_HMAC:
            m_in->inScheme.details.any.hashAlg = inScheme.details.any.hashAlg;
            break;
        default: // 对其他厂家自定义格式(或未知格式)的 Scheme 联合体, 我们不建议进行赋值操作.
            // 因此此处手动拷贝整个 details 数据块.
            TPMU_SIG_SCHEME *p;
            p = &(m_in->inScheme.details);
            memcpy(p, &(inScheme.details), sizeof(m_in->inScheme.details));
            break;
    }
    m_in->inScheme.scheme = inScheme.scheme;
}

// ============================================================================
// 常用的数字签名 schemes 选项
// ----------------------------------------------------------------------------

/// 选择用 RSASSA 密钥对 SHA1 哈希摘要进行签名
const TPMT_SIG_SCHEME DigitalSignatureSchemes::SHA1RSASSA = {
    .scheme = TPM_ALG_RSASSA,
    .details = {
        .rsassa = {
            .hashAlg = TPM_ALG_SHA1,
         },
    },
};

/// 选择用 RSASSA 密钥对 SHA256 哈希摘要进行签名
const TPMT_SIG_SCHEME DigitalSignatureSchemes::SHA256RSASSA = {
    .scheme = TPM_ALG_RSASSA,
    .details = {
        .rsassa = {
            .hashAlg = TPM_ALG_SHA256,
         },
    },
};

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
    TPMI_DH_OBJECT keyHandle;
    TPM2B_DIGEST digest;
    TPMT_SIGNATURE signature;
} VerifySignature_In;

/// 私有结构体
typedef struct Out {
    TPMT_TK_VERIFIED validation;
} VerifySignature_Out;

// ============================================================================
// 构造函数
// ----------------------------------------------------------------------------
VerifySignature::VerifySignature() {
    m_in = new VerifySignature_In;
    m_out = new VerifySignature_Out;

    /* 初始化输入缓冲区, 并设置默认值 */
    m_cmdAuthsCount = 1; // 需授权访问 keyHandle
    m_in->keyHandle = 0x80FFFFFF; // 随意设置一个无效的初始值, 便于调试程序
    m_in->digest.t.size = 0;

    /* 清空输出缓冲区 */
    memset(m_out, 0x00, sizeof(*m_out));
}

// ============================================================================
// 析构函数
// ----------------------------------------------------------------------------
VerifySignature::~VerifySignature() {
    eraseCachedAuthPassword();
    delete m_in;
    delete m_out;
}

// ============================================================================
// 指定访问签名密钥授权方式(通过哪种会话进行授权校验)
// ----------------------------------------------------------------------------
void VerifySignature::configAuthSession(TPMI_SH_AUTH_SESSION authSessionHandle) {
    m_sendAuthValues[0].sessionHandle = authSessionHandle;
}

// ============================================================================
// 指定授权值访问密码(属于敏感数据)
// ----------------------------------------------------------------------------
void VerifySignature::configAuthPassword(const void *password, UINT16 length) {
    // 调用父类的成员函数完成设置密码的具体工作
    TPMCommand::configAuthPassword(password, length);
}

// ============================================================================
// 擦除临时缓存的授权值
// ----------------------------------------------------------------------------
void VerifySignature::eraseCachedAuthPassword() {
    // 调用父类的成员函数擦除密码
    TPMCommand::eraseCachedAuthPassword();
}

// ============================================================================
// 指定数字签名操作要使用的签名密钥(不对称密钥, 可选取 RSA, ECC 等类型)
// ----------------------------------------------------------------------------
void VerifySignature::configSigningKey(TPM_HANDLE keyHandle) {
    m_in->keyHandle = keyHandle; // 此处暂时没有对密钥句柄的高八位进行检查, 高八位应该以0x80或0x81开头
}

// ============================================================================
// 同时指定待校验的数字签名字段和被签名的哈希摘要字段
// ----------------------------------------------------------------------------
void VerifySignature::configDigestWithSignature(const TPM2B_DIGEST& digest, const TPMT_SIGNATURE& signature) {
    const UINT16 MaxDigestLen = sizeof(m_in->digest.t.buffer);
    UINT16 len;

    len = digest.t.size;
    if (len > MaxDigestLen) {
        len = MaxDigestLen; // 直接截断超出长度限制的字节. 这里暂不输出错误或警告信息!
    }
    m_in->digest.t.size = len;
    memcpy(m_in->digest.t.buffer, digest.t.buffer, len);

    m_in->signature.sigAlg = signature.sigAlg;
    memcpy(&(m_in->signature.signature), &(signature.signature), sizeof(TPMU_SIGNATURE));
}

// ============================================================================
// 组建命令帧报文
// ----------------------------------------------------------------------------
void VerifySignature::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_VerifySignature_Prepare( // NOTE: 此处应检查函数返回值
            ctx, // TSS2_SYS_CONTEXT *sysContext 上下文
            m_in->keyHandle, // 指定算法
            &(m_in->digest), // 输入待签名的哈希摘要
            &(m_in->signature) // 输入待校验的数字签名
            );
    // 然后显式调用父类的成员函数
    TPMCommand::buildCmdPacket(ctx);
}

// ============================================================================
// 解码应答桢报文
// ----------------------------------------------------------------------------
void VerifySignature::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 调用父类的成员函数处理 auth value
    TPMCommand::unpackRspPacket(ctx);
    // 然后调用 API 函数进行解包
    Tss2_Sys_VerifySignature_Complete( // 通常情况下并不需要核对 Tss2_Sys_XXXX_Complete() 函数的返回码
            ctx, // TSS2_SYS_CONTEXT *sysContext 上下文
            &(m_out->validation) // 对本次校验结果出具校验凭证(validation ticket)
            );
}

// ============================================================================
// 若 TPM 判定签名校验有效, 则 TPM 应答桢中将携带一个 validation ticket, 作为辅助证明
// ----------------------------------------------------------------------------
const TPMT_TK_VERIFIED& VerifySignature::outValidationTicket() {
    return m_out->validation;
}

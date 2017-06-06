/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// ============================================================================
// 自定义输入输出参数格式
// ----------------------------------------------------------------------------

/// 私有结构体 Hash_In
typedef struct In {
    TPM2B_MAX_BUFFER data; ///< 输入数据, 长度限制:不超过 MAX_DIGEST_BUFFER=1024 字节.
    TPMI_ALG_HASH hashAlg; ///< 哈希算法代号, 当前支持 5 种取值, 分别是: TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TPM_ALG_SM3_256.
    TPMI_RH_HIERARCHY hierarchy; ///< 指定输出 ticket 时对应哪种密钥树类型, 取值可以是 TPM_RH_NULL=0x40000007 等. 该字段对应命令输出值 TPMT_TK_HASHCHECK 的 hierarchy 字段.
} Hash_In;

/// 私有结构体 Hash_Out
typedef struct Out {
    TPM2B_DIGEST outHash; ///< 输出哈希摘要结果
    TPMT_TK_HASHCHECK validation; ///< 通过 ticket 机制限定该哈希摘要数值能否被 TPM 签名. 如果输出是 NULL ticket, 则不允许使用用 restricted key 对该条哈希摘要进行签名.
} Hash_Out;

// ============================================================================
// 构造函数
// ----------------------------------------------------------------------------
Hash::Hash() {
    m_in = new Hash_In;
    m_out = new Hash_Out;

    /* 初始化输入缓冲区, 并设置默认值 */
    m_in->data.t.size = 0;
    m_in->hashAlg = TPM_ALG_SHA1;
    m_in->hierarchy = TPM_RH_NULL;

    /* 清空输出缓冲区 */
    memset(m_out, 0x00, sizeof(*m_out));

    m_cmdAuthsCount = 0; // 默认不需要授权
}

// ============================================================================
// 析构函数
// ----------------------------------------------------------------------------
Hash::~Hash() {
    delete m_in;
    delete m_out;
}

// ============================================================================
// 指定要使用哈希算法为 SHA1
// ----------------------------------------------------------------------------
void Hash::configHashAlgorithmUsingSHA1() {
    m_in->hashAlg = TPM_ALG_SHA1;
}

// ============================================================================
// 指定要使用哈希算法为 SHA256
// ----------------------------------------------------------------------------
void Hash::configHashAlgorithmUsingSHA256() {
    m_in->hashAlg = TPM_ALG_SHA256;
}

// ============================================================================
// 指定要使用哈希算法为 SHA384
// ----------------------------------------------------------------------------
void Hash::configHashAlgorithmUsingSHA384() {
    m_in->hashAlg = TPM_ALG_SHA384;
}

// ============================================================================
// 指定输入数据
// ----------------------------------------------------------------------------
void Hash::configInputData(const void *data, UINT16 length) {
    if (length > sizeof(m_in->data.t.buffer)) {
        length = sizeof(m_in->data.t.buffer); // 直接截断超出长度限制的字节. 这里暂不输出错误或警告信息!
    }
    m_in->data.t.size = length;
    memcpy(m_in->data.t.buffer, data, length);
}

// ============================================================================
// 擦除已缓存的输入数据
// ----------------------------------------------------------------------------
void Hash::eraseCachedInputData() {
    memset(m_in->data.t.buffer, 0x00, sizeof(m_in->data.t.buffer));
    m_in->data.t.size = 0;
}

// ============================================================================
// 组建命令帧报文
// ----------------------------------------------------------------------------
void Hash::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_Hash_Prepare( // NOTE: 此处应检查函数返回值
            ctx, // API 上下文
            &(m_in->data), // 输入数据
            m_in->hashAlg, // 指定算法
            m_in->hierarchy // 指定生成的 ticket 对应的密钥树类型
            );
    // 然后显式调用父类的成员函数(注: Hash 命令本身无需授权, 预留此接口仅用于HMAC校验或参数加解密)
    this->TPMCommand::buildCmdPacket(ctx);
}

// ============================================================================
// 解码应答桢报文
// ----------------------------------------------------------------------------
void Hash::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先显式调用父类的成员函数(注: Hash 命令本身无需授权, 预留此接口仅用于HMAC校验或参数加解密)
    this->TPMCommand::unpackRspPacket(ctx);
    // 然后调用 API 函数进行解包
    m_out->outHash.t.size = sizeof(m_out->outHash.t.buffer);// 此处填写最大值可以避免 Tss2_Sys_Hash_Complete() 函数返回错误码 TSS2_SYS_RC_INSUFFICIENT_BUFFER
    Tss2_Sys_Hash_Complete( // NOTE: 此处应检查函数返回值
            ctx, // API 上下文
            &(m_out->outHash), // 输出摘要
            &(m_out->validation) // 输出 ticket
            );
}

// ============================================================================
// 输出哈希计算的结果, 即摘要值
// ----------------------------------------------------------------------------
const TPM2B_DIGEST& Hash::outHash() {
    return m_out->outHash;
}

// ============================================================================
// 输出相应的 ticket 值作为辅助数据.
// 后续执行签名等操作时需要该 ticket 值作为依据.
// ----------------------------------------------------------------------------
const TPMT_TK_HASHCHECK& Hash::outValidationTicket() {
    return m_out->validation;
}

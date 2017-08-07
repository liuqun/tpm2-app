/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// ============================================================================
// 自定义输入输出参数格式
// ============================================================================

/// 私有结构体 CreatePrimary_In
typedef struct In {
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
} CreatePrimary_In;

/// 私有结构体 CreatePrimary_Out
typedef struct Out {
    TPM_HANDLE objectHandle;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
    TPM2B_NAME name;
} CreatePrimary_Out;

// ============================================================================
// 构造函数
// ============================================================================
CreatePrimary::CreatePrimary() {
    m_in = new CreatePrimary_In;
    m_out = new CreatePrimary_Out;

    /* 设置默认句柄 */
    m_in->hierarchy = TPM_RH_NULL;

    /* 输入参数: 先清空各数据块的长度字段 */
    m_in->inSensitive.t.size = 0;
    m_in->inPublic.t.size = 0; // 备忘: inPublic 作为 Tss2_Sys_CreatePrimary() 函数的输入参数时, 该 size 字段实际上是无用的, 无需手动赋值. Tss2_Sys_CreatePrimary() 函数内部会自动计算 TPM2B_PUBLIC 数据块 Marshal 之后的长度
    m_in->outsideInfo.t.size = 0; //
    m_in->creationPCR.count = 0; // 必填

    /* 详细设置输入参数的初始值: 这里我们默认将创建一个 KEYEDHASH 密钥 */
    //printf("配置默认值: 密钥类型默认将被设置成 RSA 密钥: \n");
    m_in->inPublic.t.publicArea.type = TPM_ALG_RSA;
    m_in->inPublic.t.publicArea.nameAlg = TPM_ALG_NULL;

    m_in->inPublic.t.publicArea.objectAttributes.val = 0;
    m_in->inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    m_in->inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    m_in->inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    m_in->inPublic.t.publicArea.objectAttributes.userWithAuth = 1; // 访问密钥须提供用户授权信息: 1.是 / 0.否
    m_in->inPublic.t.publicArea.objectAttributes.restricted = 1; // 密钥的用途范围是否被限定: 1.仅可对已知数据结构进行操作(我也不是很理解到底这个标记位的具体含义) / 0.否
    m_in->inPublic.t.publicArea.objectAttributes.decrypt = 1; // 不对称密钥的私钥部分是否可用于解密: 1.是 / 0.否
    m_in->inPublic.t.publicArea.objectAttributes.sign = 0; // 密钥是否可用于签名: 1.是 / 0.否

    m_in->inPublic.t.publicArea.authPolicy.t.size = 0;

    m_in->inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    m_in->inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    m_in->inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    m_in->inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    m_in->inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048; // 私钥位数

    m_in->inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
    m_in->inPublic.t.publicArea.unique.rsa.t.size = 0;

    /* 清空输出缓冲区 */
    memset(m_out, 0x00, sizeof(*m_out));

    // 基类构造函数 TPMCommand::TPMCommand() 已经对授权区域进行了初始化
    m_cmdAuthsCount = 1; // 指定使用第一个授权区域访问密钥树父节点
}

// ============================================================================
// 析构函数
// ============================================================================
CreatePrimary:: ~CreatePrimary() {
    eraseCachedAuthPassword();
    eraseCachedKeySensitiveData();
    delete m_in;
    delete m_out;
}

// ============================================================================
// 指定新的密钥树放置于哪里(需经授权校验)
// ============================================================================
void CreatePrimary::configAuthHierarchy(TPMI_RH_HIERARCHY hierarchy) {
    m_in->hierarchy = hierarchy;
}

// ============================================================================
// 组建命令帧报文
// ============================================================================
void CreatePrimary::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_CreatePrimary_Prepare(// NOTE: 此处应检查函数返回值
            ctx,
            m_in->hierarchy,
            &(m_in->inSensitive),
            &(m_in->inPublic),
            &(m_in->outsideInfo),
            &(m_in->creationPCR)
            );
    // 然后显式调用父类的成员函数完成填写 AuthValue 工作
    this->TPMCommand::buildCmdPacket(ctx);
}

// ============================================================================
// 解码应答桢报文
// ============================================================================
void CreatePrimary::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先显式调用父类的成员函数(通过该函数写入授权值)
    this->TPMCommand::unpackRspPacket(ctx);
    // 然后调用 API 函数进行解包
    m_out->outPublic.t.size = 0; // 必须填 0, 否则 Tss2_Sys_CreatePrimary_Complete() 报错 TSS2_SYS_RC_BAD_VALUE
    m_out->creationData.t.size = 0; // 必须填 0, 否则 Tss2_Sys_CreatePrimary_Complete() 报错 TSS2_SYS_RC_BAD_VALUE
    m_out->creationHash.t.size = sizeof(m_out->creationHash) - sizeof(UINT16); // 应填最大值, 否则 Tss2_Sys_CreatePrimary_Complete() 可能报错 TSS2_SYS_RC_INSUFFICIENT_BUFFER
    // m_out->creationTicket 的初始值可填可不填
    m_out->creationTicket.tag = (TPM_ST) 0;
    m_out->creationTicket.hierarchy = (TPMI_RH_HIERARCHY) 0x0;
    m_out->creationTicket.digest.t.size = sizeof(m_out->creationTicket.digest) - sizeof(UINT16);
    m_out->name.t.size = sizeof(m_out->name) - sizeof(UINT16);
    Tss2_Sys_CreatePrimary_Complete(// NOTE: 此处应检查函数返回值
            ctx,
            &(m_out->objectHandle),
            &(m_out->outPublic),
            &(m_out->creationData),
            &(m_out->creationHash),
            &(m_out->creationTicket),
            &(m_out->name)
            );
}

// ============================================================================
// 填写密钥敏感数据
// ============================================================================
void CreatePrimary::configKeySensitiveData(
        const void *keyAuthValue,
        UINT16 size,
        const void *extraSensitiveData,
        UINT16 extraDataSize
        ) {
    m_in->inSensitive.t.size = 0;
    const UINT16 MAX_AUTH_BUFSIZ = sizeof(m_in->inSensitive.t.sensitive.userAuth.t.buffer);
    if (size > MAX_AUTH_BUFSIZ) {
        size = MAX_AUTH_BUFSIZ;
    }
    m_in->inSensitive.t.sensitive.userAuth.t.size = size;
    if (size > 0)
    {
        memcpy(m_in->inSensitive.t.sensitive.userAuth.t.buffer, keyAuthValue, size);
        m_in->inSensitive.t.size += sizeof(INT16) + m_in->inSensitive.t.sensitive.userAuth.t.size;
    }
    const UINT16 MAX_EXTRA_BUFFFER_SIZE = sizeof(m_in->inSensitive.t.sensitive.data.t.buffer);
    if (extraDataSize > MAX_EXTRA_BUFFFER_SIZE) {
        extraDataSize = MAX_EXTRA_BUFFFER_SIZE;
    }
    m_in->inSensitive.t.sensitive.data.t.size = extraDataSize;
    if (extraDataSize > 0)
    {
        memcpy(m_in->inSensitive.t.sensitive.data.t.buffer, extraSensitiveData, extraDataSize);
        m_in->inSensitive.t.size += sizeof(UINT16) + extraDataSize;
    }
    m_in->inPublic.t.publicArea.objectAttributes.userWithAuth = 1; // 再次确保创建密钥时正确的标志位已经被设置
}

// ============================================================================
// 清除缓存的敏感数据
// ============================================================================
void CreatePrimary::eraseCachedKeySensitiveData() {
    memset(&(m_in->inSensitive), 0x00, sizeof(m_in->inSensitive));
}

// ============================================================================
// 指定密钥树节点名称运算采用哪种哈希算法
// ============================================================================
void CreatePrimary::configKeyNameAlg(TPMI_ALG_HASH nameAlg)
{
    m_in->inPublic.t.publicArea.nameAlg = nameAlg;
}

// ============================================================================
// 指定密钥的公开数据(按TPM2B_PUBLIC格式)
// ============================================================================
void CreatePrimary::configPublicData(const TPM2B_PUBLIC& inPublic) {
    m_in->inPublic = inPublic;
}

// ============================================================================
// 指定密钥的公开数据(按TPMT_PUBLIC格式)
// ============================================================================
void CreatePrimary::configPublicData(const TPMT_PUBLIC& publicArea) {
    m_in->inPublic.t.size = 0; // 该 size 字段可以不填, 任意值都将被底层 API 忽略
    m_in->inPublic.t.publicArea = publicArea;
}

// ============================================================================
// 输出密钥的句柄
// ============================================================================
TPM_HANDLE& CreatePrimary::outObjectHandle() {
    return m_out->objectHandle;
}

// ============================================================================
// 输出密钥的公开数据
// ============================================================================
TPM2B_PUBLIC& CreatePrimary::outPublic() {
    return m_out->outPublic;
}

// ============================================================================
// 输出用于证明该密钥是由 TPM 模块创建的 ticket 结构体
// ============================================================================
TPMT_TK_CREATION& CreatePrimary::outCreationTicket() {
    return m_out->creationTicket;
}

// ============================================================================
// 输出 TPM 模块创建密钥数据和当时的环境状态记录
// ============================================================================
TPM2B_CREATION_DATA& CreatePrimary::outCreationData() {
    return m_out->creationData;
}

// ============================================================================
// 输出 TPM2B_CREATION_DATA 结构体的哈希值
// ============================================================================
TPM2B_DIGEST& CreatePrimary::outCreationHash() {
    return m_out->creationHash;
}

// ============================================================================
// 输出新节点的节点名
// ============================================================================
const TPM2B_NAME& CreatePrimary::outName() {
    return m_out->name;
}


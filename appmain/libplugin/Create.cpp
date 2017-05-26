/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// ============================================================================
// 自定义输入输出参数格式
// ============================================================================

/// 私有结构体 Create_In
typedef struct Parameters_In {
    TPMI_DH_OBJECT parentHandle;
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;
} Create_In;

/// 私有结构体 Create_Out
typedef struct Parameters_Out {
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
} Create_Out;

const TPMI_DH_OBJECT TPM_HT_NO_HANDLE = 0xFC000000; // 仅仅用于给 parentHandle 赋初始值

// ============================================================================
// 构造函数
// ============================================================================
Create::Create() {
    m_in = new Create_In;
    m_out = new Create_Out;

    /* 设置默认句柄 */
    m_in->parentHandle = TPM_HT_NO_HANDLE; // @note 此处将初始值设置为一个无效句柄. 预防调用其他成员函数时变量未初始化

    /* 输入参数: 先清空各数据块的长度字段 */
    m_in->inSensitive.t.size = 0;
    m_in->inPublic.t.size = 0; // 备忘: inPublic 作为 Tss2_Sys_Create() 函数的输入参数时, 该 size 字段实际上是无用的, 无需手动赋值. Tss2_Sys_Create() 函数内部会自动计算 TPM2B_PUBLIC 数据块 Marshal 之后的长度
    m_in->outsideInfo.t.size = 0; //
    m_in->creationPCR.count = 0; // 必填

    /* 详细设置输入参数的初始值: 这里我们默认将创建一个 KEYEDHASH 密钥 */
    m_in->inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;

    m_in->inPublic.t.publicArea.nameAlg = TPM_ALG_NULL; // TPM 密钥树计算节点名称时使用的哈希算法, 初始值可以不设

    m_in->inPublic.t.publicArea.objectAttributes.val = (UINT32) 0; // 先清空全部标记位, 然后逐个设置
    m_in->inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    m_in->inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    m_in->inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    m_in->inPublic.t.publicArea.objectAttributes.userWithAuth = 1; // 访问密钥须提供用户授权信息
    m_in->inPublic.t.publicArea.objectAttributes.restricted = 1; // 被限定
    m_in->inPublic.t.publicArea.objectAttributes.decrypt = 0;
    m_in->inPublic.t.publicArea.objectAttributes.sign = 1; // 用于签名

    m_in->inPublic.t.publicArea.authPolicy.t.size = 0;

    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC; // 必填项
    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_NULL;

    m_in->inPublic.t.publicArea.unique.keyedHash.t.size = 0;
    m_in->inPublic.t.publicArea.unique.keyedHash.t.buffer[0] = '\0'; // 填零便于测试

    /* 清空输出缓冲区 */
    memset(m_out, 0x00, sizeof(*m_out));

    // 基类构造函数 TPMCommand::TPMCommand() 已经对授权区域进行了初始化
    m_cmdAuthsCount = 1; // 指定使用第一个授权区域访问密钥树父节点
}

// ============================================================================
// 构造函数
// ============================================================================
HMACKeyCreate::HMACKeyCreate() {
    /* 详细设置输入参数的初始值: 这里我们默认将创建一个 KEYEDHASH HMAC 密钥 */
    m_in->inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;

    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_NULL;

}

// ============================================================================
// 构造函数
// ============================================================================
XORKeyCreate::XORKeyCreate() {
    /* 详细设置输入参数的初始值: 这里我们默认将创建一个 KEYEDHASH XOR 密钥 */
    m_in->inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;

    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_XOR;
    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg = TPM_ALG_NULL;
    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf = TPM_ALG_KDF1_SP800_108;
}

// ============================================================================
// 析构函数
// ============================================================================
Create:: ~Create() {
    eraseCachedAuthPassword();
    eraseKeySensitiveData();
    delete m_in;
    delete m_out;
}

// ============================================================================
// 指定通过密钥树中哪个父节点进行授权校验
// ============================================================================
void Create::configAuthParent(TPMI_DH_OBJECT parentHandle) {
    m_in->parentHandle = parentHandle;
}

// ============================================================================
// 组建命令帧报文
// ============================================================================
void Create::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_Create_Prepare(// NOTE: 此处应检查函数返回值
            ctx,
            m_in->parentHandle,
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
void Create::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先显式调用父类的成员函数(通过该函数写入授权值)
    this->TPMCommand::unpackRspPacket(ctx);
    // 然后调用 API 函数进行解包
    m_out->outPrivate.t.size = sizeof(m_out->outPrivate) - sizeof(UINT16); // 应填最大值, 否则 Tss2_Sys_Create_Complete() 可能报错 TSS2_SYS_RC_INSUFFICIENT_BUFFER
    m_out->outPublic.t.size = 0; // 必须填 0, 否则 Tss2_Sys_Create_Complete() 报错 TSS2_SYS_RC_BAD_VALUE
    m_out->creationData.t.size = 0; // 必须填 0, 否则 Tss2_Sys_Create_Complete() 报错 TSS2_SYS_RC_BAD_VALUE
    m_out->creationHash.t.size = sizeof(m_out->creationHash) - sizeof(UINT16); // 应填最大值, 否则 Tss2_Sys_Create_Complete() 可能报错 TSS2_SYS_RC_INSUFFICIENT_BUFFER
    // m_out->creationTicket 的初始值可填可不填
    m_out->creationTicket.tag = (TPM_ST) 0;
    m_out->creationTicket.hierarchy = (TPMI_RH_HIERARCHY) 0x0;
    m_out->creationTicket.digest.t.size = sizeof(m_out->creationTicket.digest) - sizeof(UINT16);
    Tss2_Sys_Create_Complete(// NOTE: 此处应检查函数返回值
            ctx,
            &(m_out->outPrivate),
            &(m_out->outPublic),
            &(m_out->creationData),
            &(m_out->creationHash),
            &(m_out->creationTicket)
            );
}

// ============================================================================
// 填写密钥敏感数据
// ============================================================================
void Create::configKeySensitiveData(
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
        memcpy(m_in->inSensitive.t.sensitive.userAuth.t.buffer, extraSensitiveData, extraDataSize);
        m_in->inSensitive.t.size += sizeof(UINT16) + extraDataSize;
    }
    m_in->inPublic.t.publicArea.objectAttributes.userWithAuth = 1; // 再次确保创建密钥时正确的标志位已经被设置
}

// ============================================================================
// 清除缓存的敏感数据
// ============================================================================
void Create::eraseKeySensitiveData() {
    memset(&(m_in->inSensitive), 0x00, sizeof(m_in->inSensitive));
}

// ============================================================================
// 指定密钥树节点名称运算采用哪种哈希算法
// ============================================================================
void Create::configKeyNameAlg(TPMI_ALG_HASH nameAlg)
{
    m_in->inPublic.t.publicArea.nameAlg = nameAlg;
}

// ============================================================================
// 指定要密钥的公开数据
// ============================================================================
void Create::configPublicData(const TPM2B_PUBLIC& inPublic) {
    m_in->inPublic = inPublic;
}

// ============================================================================
// 指定 HMAC 密钥参数
// ============================================================================
void HMACKeyCreate::configHMACKeyParameters(TPMI_ALG_HASH hashAlg) {
    m_in->inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;

    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = hashAlg; // 指定算法

    m_in->inPublic.t.publicArea.unique.keyedHash.t.size = 0;
    m_in->inPublic.t.publicArea.unique.keyedHash.t.buffer[0] = '\0'; // 填零便于测试
}

// ============================================================================
// 指定 XOR Key 参数哈希算法和 kdf 算法
// ============================================================================
void XORKeyCreate::configXORKeyParameters(TPMI_ALG_HASH hashAlg, TPMI_ALG_KDF kdf) {
    m_in->inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;

    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_XOR;
    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.hashAlg = hashAlg; // 指定算法
    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf = kdf; // 指定密钥衍生算法

    m_in->inPublic.t.publicArea.unique.keyedHash.t.size = 0;
    m_in->inPublic.t.publicArea.unique.keyedHash.t.buffer[0] = '\0'; // 填零便于测试
}

// ============================================================================
// 输出密钥的私钥相关数据(后续调用 Load 命令时用到)
// ============================================================================
TPM2B_PRIVATE& Create::outPrivate() {
    return m_out->outPrivate;
}

// ============================================================================
// 输出密钥的公开数据(后续调用 Load 命令时用到)
// ============================================================================
TPM2B_PUBLIC& Create::outPublic() {
    return m_out->outPublic;
}

// ============================================================================
// 输出用于证明该密钥是由 TPM 模块创建的 ticket 结构体
// ============================================================================
TPMT_TK_CREATION& Create::outCreationTicket() {
    return m_out->creationTicket;
}

// ============================================================================
// 输出 TPM 模块创建密钥数据和当时的环境状态记录
// ============================================================================
TPM2B_CREATION_DATA& Create::outCreationData() {
    return m_out->creationData;
}

// ============================================================================
// 输出 TPM2B_CREATION_DATA 结构体的哈希值
// ============================================================================
TPM2B_DIGEST& Create::outCreationHash() {
    return m_out->creationHash;
}

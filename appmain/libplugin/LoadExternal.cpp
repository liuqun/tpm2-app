/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// ============================================================================
// 自定义输入输出参数格式
// ----------------------------------------------------------------------------

/// 私有结构体 LoadExternal_In
typedef struct In {
    TPM2B_SENSITIVE inPrivate;
    TPM2B_PUBLIC inPublic;
    TPMI_RH_HIERARCHY hierarchy; ///< 指定节点关联到的 hierarchy
} LoadExternal_In;

/// 私有结构体 LoadExternal_Out
typedef struct Out {
    TPM_HANDLE objectHandle;
    TPM2B_NAME name;
} LoadExternal_Out;

// ============================================================================
// 构造函数
// ----------------------------------------------------------------------------
LoadExternal::LoadExternal() {
    m_in = new LoadExternal_In;
    m_out = new LoadExternal_Out;

    // LoadExternal 命令无需授权即可使用
    m_cmdAuthsCount = 0;

    /* 指定父节点(选择默认存放区) */
    m_in->hierarchy = TPM_RH_NULL;

    /* 输入参数: 先清空各数据块的长度字段 */
    m_in->inPrivate.t.size = 0; // size 字段无需手动赋值, Tss2_Sys_LoadExternal_Prepare() 函数内部自动计算 TPM2B_SENTITIVE 数据块 Marshal 之后的最终长度
    m_in->inPublic.t.size = 0; // 同上. Tss2_Sys_LoadExternal_Prepare() 函数内部会自动计算 TPM2B_PUBLIC 数据块 Marshal 之后的最终长度

    /* 配置详细默认值: 填写 inPublic 字段默认值定义密钥类型和属性标志位 */
    m_in->inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    m_in->inPublic.t.publicArea.nameAlg = TPM_ALG_NULL; // LoadExternal 命令允许生成节点名时不进行哈希
    m_in->inPublic.t.publicArea.objectAttributes.val = 0; // 标记位全部清零(稍后逐个重新设置)
    m_in->inPublic.t.publicArea.objectAttributes.userWithAuth = 1; // 可否通过用户授权密码访问该密钥: 1.是 / 0.否
    m_in->inPublic.t.publicArea.objectAttributes.sign = 1; // 若此密钥为不对称密钥, 则标记位 sign 指示其私钥部分是否可用于签名; 若此密钥为对称密钥, 则该标记位的含义变为指示密钥可否用于对称加解密. 1.是 / 0.否
    m_in->inPublic.t.publicArea.authPolicy.t.size = 0;
    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    const TPMI_ALG_HASH DefaultHashAlg = TPM_ALG_SHA1; // 设置默认算法
    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = DefaultHashAlg;

    m_in->inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    /* 配置详细默认值: 写入 inPrivate 默认值 */
    m_in->inPrivate.t.sensitiveArea.sensitiveType = TPM_ALG_KEYEDHASH;
    memset(&(m_in->inPrivate.t.sensitiveArea.authValue), 0x00, sizeof(m_in->inPrivate.t.sensitiveArea.authValue));
    memset(&(m_in->inPrivate.t.sensitiveArea.seedValue), 0x00, sizeof(m_in->inPrivate.t.sensitiveArea.seedValue));
    memset(&(m_in->inPrivate.t.sensitiveArea.sensitive.bits), 0x00, sizeof(m_in->inPrivate.t.sensitiveArea.sensitive.bits));

    /* 清空输出缓冲区 */
    memset(m_out, 0x00, sizeof(*m_out));

}

// ============================================================================
// 析构函数
// ----------------------------------------------------------------------------
LoadExternal:: ~LoadExternal() {
    eraseCachedAuthPassword();
    memset(&(m_in->inPrivate), 0x00, sizeof(m_in->inPrivate)); // 退出前自动擦除 inPrivate 结构体中的所有数据
    delete m_in;
    delete m_out;
}

// ============================================================================
// 指定新的密钥树放置于哪里(访问hierarchy需通过授权校验)
// ----------------------------------------------------------------------------
void LoadExternal::configHierarchy(TPMI_RH_HIERARCHY hierarchy) {
    m_in->hierarchy = hierarchy;
}

// ============================================================================
// 组建命令帧报文
// ----------------------------------------------------------------------------
void LoadExternal::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_LoadExternal_Prepare(// NOTE: 此处应检查函数返回值
            ctx,
            &(m_in->inPrivate),
            &(m_in->inPublic),
            m_in->hierarchy
            );
    // 然后显式调用父类的成员函数完成填写 AuthValue 工作
    TPMCommand::buildCmdPacket(ctx);
}

// ============================================================================
// 解码应答桢报文
// ----------------------------------------------------------------------------
void LoadExternal::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先显式调用父类的成员函数(通过该函数写入授权值)
    TPMCommand::unpackRspPacket(ctx);
    // 然后调用 API 函数进行解包
    m_out->name.t.size = sizeof(m_out->name) - sizeof(UINT16);
    Tss2_Sys_LoadExternal_Complete(// NOTE: 此处应检查函数返回值
            ctx,
            &(m_out->objectHandle),
            &(m_out->name)
            );
}

// ============================================================================
// 配置(或变更)密钥授权值(或授权访问密码)
// ----------------------------------------------------------------------------
void LoadExternal::configKeyAuthValue(
        const void *keyAuthValue,
        UINT16 size
        ) {
    const UINT16 MAX_AUTH_BUFSIZ = sizeof(m_in->inPrivate.t.sensitiveArea.authValue.t.buffer);
    if (size > MAX_AUTH_BUFSIZ) {
        size = MAX_AUTH_BUFSIZ;
    }
    m_in->inPrivate.t.sensitiveArea.authValue.t.size = size;
    if (size > 0)
    {
        memcpy(m_in->inPrivate.t.sensitiveArea.authValue.t.buffer, keyAuthValue, size);
    }

    m_in->inPublic.t.publicArea.objectAttributes.userWithAuth = 1; // 再次确保创建密钥时正确的标志位已经被设置
}

// ============================================================================
// 擦除缓存的密钥授权值(授权访问密码)
// ----------------------------------------------------------------------------
void LoadExternal::eraseCachedKeyAuthValue() {
    memset(&(m_in->inPrivate.t.sensitiveArea.authValue), 0x00, sizeof(m_in->inPrivate.t.sensitiveArea.authValue));
}

// ============================================================================
// 配置用户自定义的对称密钥敏感内容(比如 HMAC 密钥的数据)
// ----------------------------------------------------------------------------
void LoadExternal::configSensitiveDataBits(const void *buffer, UINT16 dataLength) {
    const UINT16 MaxSize = sizeof(m_in->inPrivate.t.sensitiveArea.sensitive.bits.t.buffer);
    if (dataLength > MaxSize) {
        dataLength = MaxSize; // 截断并舍弃超出长度的数据
    }
    m_in->inPrivate.t.sensitiveArea.sensitive.bits.t.size = dataLength;
    memcpy(m_in->inPrivate.t.sensitiveArea.sensitive.bits.t.buffer, buffer, dataLength);
}
void LoadExternal::configSensitiveDataBits(const TPM2B_SENSITIVE_DATA& data) {
    const UINT16 MaxSize = sizeof(m_in->inPrivate.t.sensitiveArea.sensitive.bits.t.buffer);
    UINT16 size;
    if (data.t.size < MaxSize) {
        size = data.t.size;
    } else {
        size = MaxSize;
    }
    m_in->inPrivate.t.sensitiveArea.sensitive.bits.t.size = size;
    memcpy(m_in->inPrivate.t.sensitiveArea.sensitive.bits.t.buffer, data.t.buffer, size);
}

// ============================================================================
// 填写密钥类型, 当前暂时只支持以下类型
// 1. Keyed-hash key: HMAC 密钥最大长度128字节
// 2. 对称密钥: AES-128位-CFB模式
// ----------------------------------------------------------------------------
void LoadExternal::configHMACKeyUsingHashAlgorithm(TPMI_ALG_HASH hashAlg) {
    m_in->inPrivate.t.sensitiveArea.sensitiveType = TPM_ALG_KEYEDHASH;
    m_in->inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = hashAlg;
    m_in->inPublic.t.publicArea.objectAttributes.decrypt = 0; // 此选项对于对称密钥无意义, 必须赋值decrypt=0手动清零, 否则会报参数错误 TPM_RC_P=0x40, TPM_RC_SCHEME=(RC_FMT1+0x12)=0x92. (若此密钥为不对称密钥, 则标记位 decrypt 指示私钥可以用于解密之前由公钥加密生成的密文).
}
#if 0 // 暂时注释掉下列 API 接口
//void LoadExternal::configKeyTypeSymmetricAES128CFB() {
//    const TPMI_ALG_PUBLIC type = TPM_ALG_SYMCIPHER;
//
//    m_in->inPublic.t.publicArea.type = type;
//    m_in->inPrivate.t.sensitiveArea.sensitiveType = type;
//
//    TPMT_SYM_DEF_OBJECT *sym // 指向 inPublic 结构体深处的 sym 字段
//            = &(m_in->inPublic.t.publicArea.parameters.symDetail.sym);
//    sym->algorithm = TPM_ALG_AES;
//    sym->keyBits.aes = 128; ///< @see 另见宏定义 MAX_SYM_DATA: 对称密钥最大长度 =128 位
//    sym->mode.aes = TPM_ALG_CFB;
//}
//void LoadExternal::configKeyType(TPMI_ALG_PUBLIC type) {
//    m_in->inPublic.t.publicArea.type = type;
//    m_in->inPrivate.t.sensitiveArea.sensitiveType = type;
//}
//void LoadExternal::configKeyTypeXOR(TPMI_ALG_HASH hashAlg, TPMI_ALG_KDF kdf) {
//    m_in->inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
//    m_in->inPrivate.t.sensitiveArea.sensitiveType = TPM_ALG_KEYEDHASH;
//    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_XOR;
//    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = hashAlg;
//    m_in->inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.exclusiveOr.kdf = kdf;
//}
#endif

// ============================================================================
// 指定密钥的公开数据(按 TPM2B_PUBLIC 格式)
// ----------------------------------------------------------------------------
void LoadExternal::configPublicData(const TPM2B_PUBLIC& inPublic) {
    m_in->inPublic = inPublic;
}

// ============================================================================
// 指定密钥的公开数据(按 TPMT_PUBLIC 格式)
// ----------------------------------------------------------------------------
void LoadExternal::configPublicData(const TPMT_PUBLIC& publicArea) {
    m_in->inPublic.t.size = 0; // 该 size 字段可以不填, 任意值都将被底层 API 忽略
    m_in->inPublic.t.publicArea = publicArea;
}

#if 0 // 暂时注释掉下列 API 接口
//  // ============================================================================
//  // 指定密钥树节点名称运算采用哪种哈希算法
//  // ----------------------------------------------------------------------------
//  void LoadExternal::configKeyNameAlg(TPMI_ALG_HASH nameAlg)
//  {
//      m_in->inPublic.t.publicArea.nameAlg = nameAlg;
//  }
#endif

// ============================================================================
// 输出密钥的句柄
// ----------------------------------------------------------------------------
TPM_HANDLE& LoadExternal::outObjectHandle() {
    return m_out->objectHandle;
}

// ============================================================================
// 输出新节点的节点名
// ----------------------------------------------------------------------------
const TPM2B_NAME& LoadExternal::outName() {
    return m_out->name;
}

// ============================================================================
// 附录1: 伪代码展示如何手动填写 inPrivate 结构体的各个字段
// ----------------------------------------------------------------------------
//
//  TPM2B_SENSITIVE inPrivate;
//  inPrivate.t.size  = 0;
//  inPrivate.t.sensitiveArea.sensitiveType = TPM_ALG_KEYEDHASH;
//  inPrivate.t.size += sizeof(inPrivate.t.sensitiveArea.sensitiveType);
//
//  const UINT16 MaxAuthValueSize = sizeof(inPrivate.t.sensitiveArea.authValue.t.buffer);
//  const UINT16 MaxSeedValueSize = sizeof(inPrivate.t.sensitiveArea.seedValue.t.buffer);
//  const UINT16 MaxSensitiveBitsSize = sizeof(inPrivate.t.sensitiveArea.sensitive.bits.t.buffer);
//  UINT16 authValueSize;
//  UINT16 seedValueSize;
//  UINT16 sensitiveBitsSize;
//
//  authValueSize = 0;
//  if (authValueSize > MaxAuthValueSize) {
//      authValueSize = MaxAuthValueSize; // 截断并舍弃超出长度上限的数据
//  }
//  inPrivate.t.sensitiveArea.authValue.t.size = authValueSize;
//  if (authValueSize > 0) {
//      const void *authValueBuffer = "";
//      memcpy(inPrivate.t.sensitiveArea.authValue.t.buffer, authValueBuffer, authValueSize);
//  }
//  inPrivate.t.size += sizeof(UINT16) + authValueSize;
//
//  seedValueSize = 0;
//  if (seedValueSize > MaxSeedValueSize) {
//      seedValueSize = MaxSeedValueSize; // 截断并舍弃超出长度上限的数据
//  }
//  inPrivate.t.sensitiveArea.seedValue.t.size = seedValueSize;
//  if (seedValueSize > 0) {
//      const void *seedValueBuffer = "";
//      memcpy(inPrivate.t.sensitiveArea.seedValue.t.buffer, seedValueBuffer, seedValueSize);
//  }
//  inPrivate.t.size += sizeof(UINT16) + seedValueSize;
//
//  sensitiveBitsSize = 0;
//  if (sensitiveBitsSize > MaxSensitiveBitsSize) {
//      sensitiveBitsSize = MaxSensitiveBitsSize; // 截断并舍弃超出长度上限的数据
//  }
//  inPrivate.t.sensitiveArea.sensitive.bits.t.size = sensitiveBitsSize;
//  if (sensitiveBitsSize > 0) {
//      const void *sensitiveBitsBuffer = "";
//      memcpy(inPrivate.t.sensitiveArea.sensitive.bits.t.buffer, sensitiveBitsBuffer, sensitiveBitsSize);
//  }
//  inPrivate.t.size += sizeof(UINT16) + sensitiveBitsSize;

/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// ============================================================================
// 首先定义 RSAES 中的一组常量
// ============================================================================

namespace RSAES
{

/**
 * 私有结构体
 */
struct _PaddingScheme {
    TPM_ALG_ID scheme; ///< scheme selector
    TPMU_ASYM_SCHEME details; ///< scheme parameters

    /**
     * 不带任何参数的构造函数
     */
    _PaddingScheme() {
        scheme = TPM_ALG_NULL;
        memset(&details, 0x00, sizeof(details));
    }
    /**
     * 构造函数
     */
    _PaddingScheme(TPM_ALG_ID scheme=TPM_ALG_NULL) {
        this->scheme = scheme;
        memset(&details, 0x00, sizeof(details));
    }
    /**
     * 构造函数
     */
    _PaddingScheme(TPM_ALG_ID scheme, TPMI_ALG_HASH hashAlg) {
        this->scheme = scheme;
        memset(&details, 0x00, sizeof(details));
        if (TPM_ALG_OAEP == scheme) {
            this->details.oaep.hashAlg = hashAlg;
        }
    }
};

static struct _PaddingScheme INHERITED_FROM_RSA_KEY(TPM_ALG_NULL);
static struct _PaddingScheme OAEP_SHA1(TPM_ALG_OAEP, TPM_ALG_SHA1);
static struct _PaddingScheme OAEP_SHA256(TPM_ALG_OAEP, TPM_ALG_SHA256);
static struct _PaddingScheme PKCS1_V1_5(TPM_ALG_RSAES);

const PaddingScheme USING_PADDING_SCHEME_INHERITED_FROM_RSA_KEY = &INHERITED_FROM_RSA_KEY;
const PaddingScheme USING_PADDING_SCHEME_OAEP_SHA1 = &OAEP_SHA1;
const PaddingScheme USING_PADDING_SCHEME_OAEP_SHA256 = &OAEP_SHA256;
const PaddingScheme USING_PADDING_SCHEME_PKCS1_V1_5 = &PKCS1_V1_5;

const char *NO_PADDING_LABEL="";

} // end of namespace RSAES

// ============================================================================
// 记录各种哈希摘要的长度
// ============================================================================

typedef struct {
    TPM_ALG_ID hashAlg;
    UINT16 len; // Length of hash digest, 单位: 字节.
} HASH_SIZE_INFO;

static const HASH_SIZE_INFO HASH_SIZES[] = {
    {TPM_ALG_SHA1, SHA1_DIGEST_SIZE},
    {TPM_ALG_SHA256, SHA256_DIGEST_SIZE},
    {TPM_ALG_SHA384, SHA384_DIGEST_SIZE},
    {TPM_ALG_SHA512, SHA512_DIGEST_SIZE},
    {TPM_ALG_SM3_256, SM3_256_DIGEST_SIZE},
    {TPM_ALG_NULL, 0},
};

static UINT16 GetDigestLength(TPM_ALG_ID hashAlg)
{
    const int N = sizeof(HASH_SIZES) / sizeof(HASH_SIZE_INFO);
    UINT16 result;

    result = 0;
    for(int i=0; i<N; i++)
    {
        if(HASH_SIZES[i].hashAlg == hashAlg)
        {
            result = HASH_SIZES[i].len;
            break;
        }
    }
    // If hash_alg was not included from the table, return value will be set to 0
    return(result);
}

// ============================================================================
// 自定义输入输出参数格式
// ============================================================================

// 私有结构体
typedef struct In{
    TPMI_DH_OBJECT keyHandle; ///< The handle of an RSA key.
    TPM2B_PUBLIC_KEY_RSA data; ///< Stores the input data. 用于缓存加密或解密前的输入数据
    TPMT_RSA_DECRYPT inScheme; ///< The padding scheme to use when the scheme associated with that RSA key is TPM_ALG_NULL: 1. 仅当密钥keyHandle内部未关联指定scheme配置时, 该值才起作用; 2. TPM具有三种可选的padding schemes: OAEP填充方案, PKCS#1-v1.5填充方案, 以及不进行填充;
    TPM2B_DATA label;
} RSA_EncryptDecrypt_In;

// 私有结构体
typedef struct Out {
    TPM2B_PUBLIC_KEY_RSA data;
} RSA_EncryptDecrypt_Out;

// ============================================================================
// 以下为 TPMCommands::Encrypt 类的实现代码
// ============================================================================

// 构造函数
// --------
Encrypt::Encrypt()
{
    m_in = new RSA_EncryptDecrypt_In;
    m_out = new RSA_EncryptDecrypt_Out;
    memset(m_out, 0x00, sizeof(*m_out));
    m_in->keyHandle = 0xFF000000; // 初始化为无效句柄便于调试
    m_in->inScheme.scheme = TPM_ALG_NULL;
    m_in->label.t.size = 0;
}

// 析构函数
// --------
Encrypt::~Encrypt()
{
    eraseCachedInputData();
    delete m_in;
    delete m_out;
}

// 组建命令帧报文
// --------------
void Encrypt::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_RSA_Encrypt_Prepare( // NOTE: 此处应检查函数返回值
            ctx,
            m_in->keyHandle,
            &(m_in->data),
            &(m_in->inScheme),
            &(m_in->label)
            );
    // 注: RSA 加密过程只使用密钥的公钥部分, 所以不需要核对授权密码
    // 这里就不需要额外调用父类的成员函数 TPMCommand::buildCmdPacket()
}

// 解码应答桢报文
// --------------
void Encrypt::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 调用 API 函数进行解包
    m_out->data.t.size = sizeof(m_out->data.t.buffer);
    Tss2_Sys_RSA_Encrypt_Complete(ctx, &(m_out->data)); // NOTE: 此处应检查函数返回值
    // 注: RSA 加密过程只使用密钥的公钥部分, 所以不需要核对授权密码
    // 这里就不需要额外调用父类的成员函数 TPMCommand::unpackRspPacket()
}

// 按 TPM2B 格式输出加密结果
// -------------------------
const TPM2B& Encrypt::out() {
    return m_out->data.b;
}

// 参数设置
// --------
// @note 另请查阅头文件中设定的每个参数的默认值及说明
void Encrypt::config(
        const void *sensitiveMessage,
        UINT16 length,
        UINT16 keyBits,
        TPM_HANDLE pubKeyHandle,
        const RSAES::PaddingScheme paddingScheme,
        const char *szPaddingLabel
        ) {
    const UINT16 RSAKeyLength = (keyBits/8); // 将RSA密钥位数转换成字节数, 以便于计算
    UINT16 maxLength;

    maxLength = sizeof(m_in->data) - sizeof(INT16);

    if (maxLength > RSAKeyLength) {
        maxLength = RSAKeyLength;
    }

    if (TPM_ALG_OAEP == paddingScheme->scheme) {
        const TPMI_ALG_HASH hashAlg = paddingScheme->details.oaep.hashAlg;
        const UINT16 hashDigestLength = GetDigestLength(hashAlg);
        maxLength -= (2 + hashDigestLength*2);
        m_in->inScheme.scheme = TPM_ALG_OAEP;
        m_in->inScheme.details.oaep.hashAlg = paddingScheme->details.oaep.hashAlg;
    } else if (TPM_ALG_RSAES == paddingScheme->scheme) {
        maxLength -= 11;
        m_in->inScheme.scheme = TPM_ALG_RSAES;
    } else { // 此时无法确定具体的填充方案, 和允许加密的最大字节数
        m_in->inScheme.scheme = TPM_ALG_NULL;
    }

    if (length > maxLength) {
        length = maxLength; // 自动截断过长的输入数据, 防止 TPM 应答桢报错, 另外也防止本地内存读写溢出
    }
    memcpy(m_in->data.t.buffer, sensitiveMessage, length);
    m_in->data.t.size = length;
    m_in->keyHandle = pubKeyHandle;

    // 填写 m_in->label 字段: 需注意 TPM2.0 标准要求 label.t.buffer[] 末尾必须含有一个'\0'作为终止符. 事实上label前面已经提供了size字段指明长度, 没有必要再画蛇添足放置一个'\0'了. 不清楚 TPM2.0 为什么强制要求用户迎合她这种蹩脚的设计
    const size_t n = strlen(szPaddingLabel);
    const size_t MaxBufferSize = sizeof(m_in->label.t.buffer);
    if (n+1 > MaxBufferSize) {
        m_in->label.t.size = MaxBufferSize;
        memcpy(m_in->label.t.buffer, szPaddingLabel, MaxBufferSize-1);
        m_in->label.t.buffer[MaxBufferSize] = '\0';
    } else if (0 == n) {
        m_in->label.t.size = 0;
    } else {
        m_in->label.t.size = n+1;
        memcpy(m_in->label.t.buffer, szPaddingLabel, n);
        m_in->label.t.buffer[n] = '\0';
    }
}

// 擦除缓存的输入数据
// ------------------
void Encrypt::eraseCachedInputData() {
    memset(&(m_in->data), 0x00, sizeof(m_in->data));
}

// ============================================================================
// 自定义一组无符号数大小比较函数
// ============================================================================

static inline unsigned MinValue(unsigned a, unsigned b) {
    return ((a<=b)? a:b);
}

static inline unsigned MaxValue(unsigned a, unsigned b) {
    return ((a>=b)? a:b);
}

// ============================================================================
// 以下为 TPMCommands::Decrypt 类的实现代码
// ============================================================================

// 参数设置
// --------
// @note 另请查阅头文件中设定的每个参数的默认值及说明
void Decrypt::config(const void *encryptedData, // 输入密文书籍
        UINT16 dataLen, // 密文数据的长度
        UINT16 keyBits, // RSA 密钥位数
        TPM_HANDLE privKeyHandle, // RSA 私钥句柄
        const RSAES::PaddingScheme paddingScheme, // RSA 加解密填充方案
        const char *szPaddingLabel // 可选的填充label
        ) {
    const UINT16 RSAKeyLen = (keyBits/8); // 将RSA密钥位数转换成字节数, 以便于计算
    if (dataLen > RSAKeyLen) {
        dataLen = RSAKeyLen; // 自动截断过长的输入数据, 防止 TPM 应答桢报错, 也防止本地内存读写溢出
    }
    const UINT16 maxBufLen = sizeof(m_in->data) - sizeof(INT16);
    if (dataLen > maxBufLen) {
        dataLen = maxBufLen; // 自动截断过长的输入数据, 防止本地内存读写溢出
    }
    m_in->data.t.size = MinValue(maxBufLen, RSAKeyLen);
    size_t offset = 0;
    if (dataLen < RSAKeyLen) { // 输入数据块长度不足时, 设法前置补零对齐, 共补填offset个字节
        offset = m_in->data.t.size - dataLen;
        memset(m_in->data.t.buffer, 0x00, offset);
    }
    memcpy(m_in->data.t.buffer+offset, encryptedData, dataLen);

    m_in->keyHandle = privKeyHandle;

    if (TPM_ALG_OAEP == paddingScheme->scheme) {
        m_in->inScheme.scheme = TPM_ALG_OAEP;
        m_in->inScheme.details.oaep.hashAlg = paddingScheme->details.oaep.hashAlg;
    } else if (TPM_ALG_RSAES == paddingScheme->scheme) {
        m_in->inScheme.scheme = TPM_ALG_RSAES;
    } else { // 用户可能输入其他此处尚未支持的填充方案编码, 直接忽略即可
        m_in->inScheme.scheme = TPM_ALG_NULL;
    }

    // 填写 m_in->label 字段: 需注意 TPM2.0 标准要求 label.t.buffer[] 末尾必须含有一个'\0'作为终止符. 事实上label前面已经提供了size字段指明长度, 没有必要再画蛇添足放置一个'\0'了. 不清楚 TPM2.0 为什么强制要求用户迎合她这种蹩脚的设计
    // The size of label includes the terminating null.
    // @see Page.89 of TPM 2.0 Part3: https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
    const size_t n = strlen(szPaddingLabel);
    const size_t MaxBufferSize = sizeof(m_in->label.t.buffer);
    if (n+1 > MaxBufferSize) {
        m_in->label.t.size = MaxBufferSize;
        memcpy(m_in->label.t.buffer, szPaddingLabel, MaxBufferSize-1);
        m_in->label.t.buffer[MaxBufferSize] = '\0';
    } else if (0 == n) {
        m_in->label.t.size = 0;
    } else {
        m_in->label.t.size = n+1;
        memcpy(m_in->label.t.buffer, szPaddingLabel, n);
        m_in->label.t.buffer[n] = '\0';
    }
}

// 构造函数
// --------
Decrypt::Decrypt()
{
    m_in = new RSA_EncryptDecrypt_In;
    m_out = new RSA_EncryptDecrypt_Out;
    memset(m_out, 0x00, sizeof(*m_out));
    m_in->keyHandle = 0xFF000000; // 初始化为无效句柄便于调试
    m_in->inScheme.scheme = TPM_ALG_NULL;
    m_in->label.t.size = 0;
    // 使用 RSA 私钥进行解密, 必须提供授权区域
    m_cmdAuthsCount = 1;
}

// 析构函数
// --------
Decrypt::~Decrypt()
{
    eraseCachedAuthPassword();
    eraseCachedOutputData();
    delete m_in;
    delete m_out;
}

// 指定访问授权方式(通过哪种会话进行授权校验)
// ------------------------------------------
void Decrypt::configAuthSession(
        TPMI_SH_AUTH_SESSION authSessionHandle ///< 会话句柄, 可选取值包括: 明文密码授权会话句柄 TPM_RS_PW 或其他 HMAC/Policy 会话句柄
        ) {
    m_sendAuthValues[0].sessionHandle = authSessionHandle;
}

// 指定授权值访问密码(属于敏感数据)
// --------------------------------
void Decrypt::configAuthPassword(const void *password, UINT16 length) {
    TPMS_AUTH_COMMAND& cmdAuth ///< an alias for m_sendAuthValues[0]
            =m_sendAuthValues[0];

    cmdAuth.nonce.t.size = 0;
    cmdAuth.sessionAttributes.val = 0;
    if (length > sizeof(cmdAuth.hmac.t.buffer)) {
        length = sizeof(cmdAuth.hmac.t.buffer); // 舍弃过长的字符, 防止溢出
    }
    memcpy((void *) cmdAuth.hmac.t.buffer, password, length);
    cmdAuth.hmac.t.size = length;
}

// 擦除临时缓存的授权值
// --------------------
void Decrypt::eraseCachedAuthPassword() {
    TPMS_AUTH_COMMAND& cmdAuth ///< an alias for m_sendAuthValues[0]
            =m_sendAuthValues[0];
    memset((void *) cmdAuth.hmac.t.buffer, 0x00, sizeof(cmdAuth.hmac.t.buffer));
    cmdAuth.hmac.t.size = 0;
}

// 组建命令帧报文
// --------------
void Decrypt::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_RSA_Decrypt_Prepare( // NOTE: 此处应检查函数返回值
            ctx, // 上下文
            m_in->keyHandle, // 私钥句柄
            &(m_in->data), // 密文数据
            &(m_in->inScheme), // 指定 RSA 填充方案
            &(m_in->label) // 指定填充方案附带的 label 标签
            );
    // 然后显式调用父类的成员函数填写命令桢中携带的授权数据
    TPMCommand::buildCmdPacket(ctx);
}

// 解码应答桢报文
// --------------
void Decrypt::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用父类的成员函数取回应答桢中携带的授权数据
    TPMCommand::unpackRspPacket(ctx);
    // 调用 API 函数进行解包
    m_out->data.t.size = sizeof(m_out->data.t.buffer);
    Tss2_Sys_RSA_Decrypt_Complete(ctx, &(m_out->data)); // NOTE: 此处应检查函数返回值
}

// 输出 RSA 解密结果
// -----------------
const TPM2B& Decrypt::out() {
    return(m_out->data.b);
}

// 擦除已缓存的输出结果
// --------------------
void Decrypt::eraseCachedOutputData() {
    memset(&(m_out->data), 0x00, sizeof(m_out->data));
}

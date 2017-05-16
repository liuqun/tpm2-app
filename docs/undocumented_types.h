/// @file undocumented_types.h
///
/// @warning This file is written for doxygen tools only! Please don't include
/// this header file in your C/C++ code!
///
/// @brief Detailed informations for several TPM2B_* structure definitions
///
/// @details In <sapi/tpmb.h>, the upstream maintainers provided the following
/// micros to build their TPM2B_*
/// structures:
/// ```
/// #define TPM2B_TYPE(name, bytes)  \
///     typedef union {              \
///     struct  {                    \
///         UINT16  size;            \
///         BYTE    buffer[(bytes)]; \
///     } t;                         \
///     TPM2B   b;                   \
///     } TPM2B_##name
///
/// #define TPM2B_TYPE1(name, bytes, bufferName) \
///     typedef union {                          \
///     struct  {                                \
///         UINT16  size;                        \
///         BYTE    bufferName[(bytes)];         \
///     } t;                                     \
///     TPM2B   b;                               \
///     } TPM2B_##name
///
/// #define TPM2B_TYPE2(name, type, bufferName ) \
///     typedef union {                          \
///     struct  {                                \
///         UINT16  size;                        \
///         type bufferName;                     \
///     } t;                                     \
///     TPM2B   b;                               \
///     } TPM2B_##name
/// ```
/// Unfortunately, doxygen (and most C/C++ IDE's) could not understand these
/// code tricks. I decided to fix those broken structure references by hand
/// before anyone could give a better solution.
///
/// @see TPM2B_TYPE
/// @see TPM2B_TYPE1
/// @see TPM2B_TYPE2

/*
 * TPM2B_* structure detailed definitions (coded by hand).
 */

/**
 * TPM 2.0 digest structure (with a UINT16 size indicator)
 *
 * ```
 * // Sample code showing the usage of TPM2B_DIGEST structure and its members
 * #include <string.h>
 * #include <sapi/tpm20.h>
 *
 * void foobar() {
 *     TPM2B_DIGEST sha1digest;
 *
 *     sha1digest.t.size = SHA1_DIGEST_SIZE;
 *     memset(sha1digest.t.buffer, 0x00, SHA1_DIGEST_SIZE); // clear data
 * }
 * ```
 * @details
 * This structure is designed as a scalable-sized buffer.
 *
 * @throws IndexOutOfBoundsException: Size indicator should NEVER be set larger
 * than the longest digest length produced by each implemented hash algorithm.
 * The max buffer size may be  64, 48, 32 or even only 20 bytes, which depends
 * on the actual size of TPMU_HA inside the libsapi's binary distribution.
 *
 * @see https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf ,
 * Chapter 10.4.2
 * Table 73: Definition of TPM2B_DIGEST Structure
 */
typedef union {
    struct {
        UINT16 size;
        BYTE buffer[sizeof(TPMU_HA)];
    } t;
    TPM2B b;
} TPM2B_DIGEST;

/**
 * TPM 2.0 key sensitive data storage area (with a UINT16 size indicator).
 * Mostly used by Tss2_Sys_LoadExternal().
 * ```
 * // Pseudo-code showing the usage of TPM2B_Sensitive and Tss2_Sys_LoadExternal()
 *
 * TPM2B_SENSITIVE inPrivate;
 * TPM2B_AUTH newAuthValue;
 * TPM2B_DIGEST seed;
 * TPM2B_SENSITIVE_DATA key; // An external key's length and secret bits
 *
 * inPrivate.t.size = 0;
 *
 * inPrivate.t.sensitiveArea.sensitiveType = (TPMI_ALG_PUBLIC) TPM_ALG_KEYEDHASH;
 * inPrivate.t.size += sizeof(TPMI_ALG_PUBLIC);
 *
 * inPrivate.t.sensitiveArea.authValue = newAuthValue = ...;
 * inPrivate.t.size += (newAuthValue.b.size + sizeof(newAuthValue.b.size));
 *
 * inPrivate.t.sensitiveArea.seedValue = seed = ...;
 * inPrivate.t.size += (seed.b.size + sizeof(seed.b.size));
 *
 * inPrivate.t.sensitiveArea.sensitive.bits = key = ...;
 * inPrivate.t.size += (key.b.size + sizeof(key.b.size));
 *
 * Tss2_Sys_LoadExternal(
 *     sysContext,
 *     &cmdAuthsArray,
 *     &inPrivate, // Here TPM2B_SENSITIVE is used as an input parameter
 *     &inPublic,
 *     TPM_RH_NULL,
 *     keyHandle,
 *     keyName,
 *     &rspAuthsArray
 *     );
 * ```
 *
 * @details
 * TPM2B_* wrapper of TPMT_SENSITIVE.
 *
 * @see TPMT_SENSITIVE
 *
 * @see TPM2B_PRIVATE_KEY_RSA
 * @see TPM2B_ECC_PARAMETER
 * @see TPM2B_SENSITIVE_DATA
 * @see TPM2B_SYM_KEY
 * @see TPM2B_PRIVATE_VENDOR_SPECIFIC
 *
 * @see Tss2_Sys_LoadExternal()
 *
 * @see https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf ,
 * Chapter 12.3.3
 * Table 196:  Definition of TPM2B_SENSITIVE Structure
 */
typedef	union {
    struct {
        UINT16 size;
        TPMT_SENSITIVE sensitiveArea;
    } t;
    TPM2B b;
} TPM2B_SENSITIVE;

/**
 * Wrapper of TPMS_SENSITIVE_CREATE
 *
 * @details 此结构体和 TPMS_SENSITIVE_CREATE 仅用于设置:
 * 1. 密钥节点的访问授权信息 TPM2B_AUTH userAuth, 长度不能超过密钥树节点名称中哈希摘要的长度
 * 2. 敏感数据 TPMS_SENSITIVE_DATA data
 * @see TPM2B_AUTH
 * @see TPM2B_SENSITIVE_DATA
 *
 * ```
 * // Pseudo-code showing the usage of TPM2B_SENSITIVE_CREATE
 * void foobar(const char *password)
 * {
 *     TPM2B_SENSITIVE_CREATE inSensitive;
 *
 *     inSensitive.t.sensitive.userAuth.t.size = strlen(password);
 *     memcpy(inSensitive.t.sensitive.userAuth.t.buffer, password, inSensitive.t.sensitive.userAuth.t.size);
 *     inSensitive.t.sensitive.data.t.size = 0;
 *
 *     // ...
 *
 *     Tss2_Sys_Create(
 *         sysContext,
 *         parentHandle,
 *         &cmdAuthsArray,
 *         &inSensitive,  // Here TPM2B_SENSITIVE_CREATE is used as an input parameter
 *         &inPublic,
 *         &outsideInfo,
 *         &creationPCR,
 *         &outPrivate, // 前面输入的密码字段 userAuth 被 TPM 解析后, 回传到输出参数 outPrivate.buffer[sizeof(_PRIVATE)] 内部.
 *         &outPublic,
 *         &creationData,
 *         &creationHash,
 *         &creationTicket,
 *         &rspAuthsArray
 *         );
 *     return;
 * }
 * ```
 *
 * @see Tss2_Sys_Create() / Tss2_Sys_CreatePrimary()
 * @see TPMS_SENSITIVE_CREATE / TPM2B_AUTH / TPM2B_SENSITIVE_DATA
 * @see 如何从 TPM2B_PRIVATE 中解析 _PRIVATE::sensitive.sensitiveArea.authValue 字段
 * @see [TPM-Rev-2.0-Part-2-Structures-01.38.pdf](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf) ,
 * Chapter 11.1.15
 * Table 138: Definition of TPM2B_SENSITIVE_CREATE Structure
 */
typedef union {
    struct {
        UINT16 size; ///< @note This size indicator will always be ignored by Tss2_Sys_Create() / Tss2_Sys_CreatePrimary().
        TPMS_SENSITIVE_CREATE sensitive;
    } t;
    TPM2B b;
} TPM2B_SENSITIVE_CREATE;

/**
 * Member field of TPMS_SENSITIVE_CREATE:
 * May be a symmetric key (1024 bit) or some sealed data (128 bytes).
 *
 * @see Bit-field sensitiveDataOrigin in TPMA_OBJECT objectAttribuites (a member field of TPMT_PUBLIC/TPM2B_PUBLIC)
 * @see Tss2_Sys_Create() / Tss2_Sys_CreatePrimary()
 * @see [TPM-Rev-2.0-Part-2-Structures-01.38.pdf](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf) ,
 * Chapter 11.1.14
 * Table 138: Definition of TPM2B_SENSITIVE_DATA Structure
 */
typedef union {
    struct {
        UINT16 size;
        BYTE buffer[MAX_SYM_DATA];
    } t;
    TPM2B b;
} TPM2B_SENSITIVE_DATA;

/**
 * TPM 2.0 key creation private data storage structure
 * (with a UINT16 size indicator)
 *
 * ```
 * // C++ pseudo-code showing the usage of TPM2B_PRIVATE
 *
 * TPM2B_PRIVATE outPrivate;
 *
 * // Call Tss2_Sys_Create()
 * Tss2_Sys_Create(
 *     sysContext,
 *     parentHandle,
 *     &cmdAuthsArray,
 *     &inSensitive,
 *     &inPublic,
 *     &outsideInfo,
 *     &creationPCR,
 *     &outPrivate, // Here TPM2B_PRIVATE is used as an output parameter
 *     &outPublic,
 *     &creationData,
 *     &creationHash,
 *     &creationTicket,
 *     &rspAuthsArray
 *     );
 *
 * TPM2B_PRIVATE& inPrivate = outPrivate; // C++ coding syntax
 *
 * // Call Tss2_Sys_Load()
 * Tss2_Sys_Load(
 *     sysContext,
 *     parentHandle,
 *     &cmdAuthsArray,
 *     &inPrivate, // Here TPM2B_PRIVATE is used as an input parameter
 *     &inPublic,
 *     &keyHandle,
 *     &keyName,
 *     &rspAuthsArray
 *     );
 * ```
 * @note
 * The buffer of TPM2B_PRIVATE comes to be a _PRIVATE structure, which holds 3
 * more data blocks: integrityOuter digest, integrityInner digest and a
 * TPM2B_SENSITIVE structure.
 * And deep inside the TPM2B_SENSITIVE structure, it holds a TPMT_SENSITIVE
 * sensitiveArea (for example a private key).
 *
 * @see _PRIVATE
 * @see TPM2B_SENSITIVE
 * @see TPMT_SENSITIVE
 *
 * @see https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf ,
 * Chapter 12.3.7
 * Table 198: Definition of TPM2B_PRIVATE Structure
 */
typedef union {
    struct {
        UINT16 size;
        BYTE buffer[sizeof(_PRIVATE)];
    } t;
    TPM2B b;
} TPM2B_PRIVATE;

/**
 * TPM 2.0 key creation public data storage structure
 * (with a UINT16 size indicator)
 *
 * ```
 * // Pseudo-code showing the usage of TPM2B_PUBLIC
 *
 * TPM2B_PUBLIC keyPublicSettings;
 *
 * keyPublicSettings.t.size = 0; // 备忘: 作为Tss2_Sys_Create()函数的输入参数时, 该size字段实际上是无用的,
 *                               //       无需手动赋值(Tss2_Sys_Create函数内部会自动计算TPM2B_PUBLIC数据块的长度)
 * keyPublicSettings.t.publicArea.type = TPM_ALG_KEYEDHASH; // 取值可选: TPM_ALG_RSA, TPM_ALG_ECC, TPM_ALG_SYMCIPHER 等等
 * keyPublicSettings.t.publicArea.nameAlg
 *         = TPM_ALG_NULL; // TPM 密钥树计算节点名称时使用的哈希算法, 初始值可以不设
 *                         // 可选取值: TPM_ALG_NULL, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384,
 *                         //           TPM_ALG_SHA512, TPM_ALG_SM3_256
 * keyPublicSettings.t.publicArea.objectAttributes.val = (UINT32) 0; // 先清空全部标记位, 然后逐个设置
 * keyPublicSettings.t.publicArea.objectAttributes.fixedTPM = 1;
 * keyPublicSettings.t.publicArea.objectAttributes.fixedParent = 1;
 * keyPublicSettings.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
 * keyPublicSettings.t.publicArea.objectAttributes.userWithAuth = 1; // 访问密钥是否须提供用户授权信息
 * keyPublicSettings.t.publicArea.objectAttributes.restricted = 1; // 是否被限定
 * keyPublicSettings.t.publicArea.objectAttributes.decrypt = 0;
 * keyPublicSettings.t.publicArea.objectAttributes.sign = 1; // 是否用于签名
 * keyPublicSettings.t.publicArea.authPolicy.t.size = 0; // 授权策略(可选)
 * if (TPM_ALG_KEYEDHASH == keyPublicSettings.t.publicArea.type) {
 *     // Keyed-Hash 密钥的填法
 *     keyPublicSettings.t.publicArea.parameters.keyedHashDetail.scheme.scheme
 *             = TPM_ALG_HMAC; // 可选取值: TPM_ALG_HMAC / TPM_ALG_XOR
 *     keyPublicSettings.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg
 *             = TPM_ALG_SHA1; // 可选取值: TPM_ALG_NULL, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384,
 *                             //           TPM_ALG_SHA512, TPM_ALG_SM3_256
 * } else if (TPM_ALG_RSA == keyPublicSettings.t.publicArea.type) {
 *     // RSA 密钥的填法
 *     keyPublicSettings.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES; // 内置对称密钥类型
 *     keyPublicSettings.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128; // 对称密钥长度
 *     keyPublicSettings.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
 *     keyPublicSettings.t.publicArea.parameters.rsaDetail.scheme.scheme
 *             = TPM_ALG_NULL; // 取值可选: TPM_ALG_NULL, TPM_ALG_RSAPSS, TPM_ALG_RSASSA, TPM_ALG_RSAES, TPM_ALG_OAEP
 *     keyPublicSettings.t.publicArea.parameters.rsaDetail.keyBits = 2048; // RSA 密钥长度: 1024 / 2048 / 4096
 *     keyPublicSettings.t.publicArea.parameters.rsaDetail.exponent = 0;
 *     keyPublicSettings.t.publicArea.unique.rsa.t.size = 0;
 * }
 * keyPublicSettings.t.publicArea.unique.keyedHash.t.size = 0;
 * keyPublicSettings.t.publicArea.unique.keyedHash.t.buffer[0] = '\0'; // 填零便于测试
 *
 * TPM2B_PUBLIC keyPublicResult;
 *
 * // Call Tss2_Sys_Create()
 * Tss2_Sys_Create(
 *     sysContext,
 *     parentHandle,
 *     &cmdAuthsArray,
 *     &inSensitive,
 *     &keyPublicSettings, // Here TPM2B_PUBLIC is used as an input templete
 *     &outsideInfo,
 *     &creationPCR,
 *     &outPrivate,
 *     &keyPublicResult, // Here TPM2B_PUBLIC is used as an output result of the input templete
 *     &creationData,
 *     &creationHash,
 *     &creationTicket,
 *     &rspAuthsArray
 *     );
 *
 * TPM2B_PUBLIC& inPublic = keyPublicResult; // C++ coding syntax
 *
 * // Call Tss2_Sys_Load()
 * Tss2_Sys_Load(
 *     sysContext,
 *     parentHandle,
 *     &cmdAuthsArray,
 *     &inPrivate,
 *     &inPublic, // Here TPM2B_PUBLIC is used as an input parameter for Tss2_Sys_Load()
 *     &keyHandle,
 *     &keyName,
 *     &rspAuthsArray
 *     );
 * ```
 *
 * @details
 * The detail data inside TPM2B_PUBLIC was defined in the following structures:
 * @see TPMT_PUBLIC
 * @see TPMA_OBJECT
 * @see TPMU_PUBLIC_PARMS
 * @see TPMS_KEYEDHASH_PARMS / TPMS_SYMCIPHER_PARMS / TPMS_RSA_PARMS / TPMS_ECC_PARMS / TPMS_ASYM_PARMS
 * @see TPMU_PUBLIC_ID
 *
 * @see https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf ,
 * Chapter 12.2.5
 * Table 191: Definition of TPM2B_PUBLIC Structure
 */
typedef union {
    struct {
        /// @brief A reserved UINT16 size field
        /// @note The value of this field will always be ignored by every Tss2_Sys_XXXX methord, including Tss2_Sys_Create() and Tss2_Sys_Load()
        UINT16 size;

        /// @brief The key's public info
        /// (including its cypher algorithm ID, key length, public key info and key name hash methord)
        TPMT_PUBLIC publicArea;
    } t;
    TPM2B b;
} TPM2B_PUBLIC;

/**
 * TPM 2.0 key name storage wrapper structure.
 *
 * @warning TPM 密钥名称的概念定义并不是我们常识中的字符串名称,
 * 而是一个由 20 字节哈希摘要数值加上 2 字节哈希算法编号组成的二进制数据
 * (此处假定配置该密钥节点时指定以 SHA1 算法存储密钥名称)
 *
 * @note 普通密钥节点的密钥名称与密钥树主节点的密钥名称的格式完全不同, 详见 TPMU_NAME
 * @see TPMU_NAME: “密钥树主节点的密钥名称”和“普通密钥节点的密钥名称”的格式定义(C 语言 union 联合体)
 *
 * ```
 * //Pseudo-code showing the usage of TPM2B_NAME
 * TPM2B_NAME keyName;
 * TPM2B_PUBLIC inPublic;
 * info.t.publicArea.nameAlg = TPM_ALG_SHA1;
 * // ...
 * Tss2_Sys_Load(
 *     sysContext,
 *     parentHandle,
 *     &cmdAuthsArray,
 *     &inPrivate,
 *     &inPublic,
 *     &keyHandle,
 *     &keyName, // Here TPM2B_NAME is used as an output parameter.
 *     &rspAuthsArray
 *     );
 * ```
 *
 * @details 密钥名称长度 size 取决于 TPM 密钥树创建该节点时指定的密钥名称哈希算法
 * (即 TPMT_PUBLIC 结构体的成员变量 nameAlg). 伪代码描述如下:
 * ```
 * TPM2B_PUBLIC inPublic;
 * inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;
 * if (inPublic.t.publicArea.nameAlg == TPM_ALG_SHA1) {
 *     keyName.t.size = SHA1_DIGEST_SIZE + sizeof(TPMI_ALG_HASH); // 即 22 字节
 * }
 * else if (inPublic.t.publicArea.nameAlg == TPM_ALG_SHA256) {
 *     keyName.t.size = SHA256_DIGEST_SIZE + sizeof(TPMI_ALG_HASH); // 即 34 字节
 * }
 * else if (inPublic.t.publicArea.nameAlg == TPM_ALG_SHA384) {
 *     keyName.t.size = SHA384_DIGEST_SIZE + sizeof(TPMI_ALG_HASH); // 即 50 字节
 * }
 * else if (inPublic.t.publicArea.nameAlg == TPM_ALG_SHA512) {
 *     keyName.t.size = SHA512_DIGEST_SIZE + sizeof(TPMI_ALG_HASH); // 即 66 字节
 * }
 * else if (inPublic.t.publicArea.nameAlg == TPM_ALG_SM3_256) {
 *     keyName.t.size = SM3_256_DIGEST_SIZE + sizeof(TPMI_ALG_HASH); // 即 32 字节
 * }
 * else {
 *     if (inPublic.t.publicArea.nameAlg == TPM_ALG_NULL) {
 *         // 如果指定使用的哈希算法时填写的是 TPM_ALG_NULL
 *         // 则 keyName.t.size 值可能取决于具体硬件或 Simulator 模拟器的具体实现
 *     }
 * }
 * ```
 *
 * @note TPM2B_NAME and TPMU_NAME were only 2 wrapper layers of TPMT_HA.
 *
 * @see TPMT_HA: The true data structure inside TPM2B_NAME and TPMU_NAME.
 *
 * @see [TPM-Rev-2.0-Part-2-Structures-01.38.pdf](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf) ,
 * Chapter 10.5.3
 * Table 84: Definition of TPM2B_NAME Structure
 */
typedef union {
    struct  {
        UINT16 size;
        BYTE name[sizeof(TPMU_NAME)];
    } t;
    TPM2B b;
} TPM2B_NAME;

/**
 * TPM 2.0 key creation data wrapper structure.
 *
 * @details
 * This structure is an output parameter created by TPM2_Create() and
 * TPM2_CreatePrimary(). TPM2B_CREATION_DATA that created by those API functions
 * should always have a non-zero size.
 *
 * The contents of TPMS_CREATION_DATA will NEVER be entered into or be saved by
 * the TPM.
 *
 * ```
 * //Pseudo-code showing the usage of TPM2B_CREATION_DATA
 * TPM2B_CREATION_DATA creationData; // NOTE: 不需要初始化
 *
 * TSS2_RC err = Tss2_Sys_Create(
 *     sysContext,
 *     parentHandle,
 *     &cmdAuthsArray,
 *     &inSensitive,
 *     &inPublic,
 *     &outsideInfo,
 *     &creationPCR,
 *     &outPrivate,
 *     &outPublic,
 *     &creationData, // TPM2B_CREATION_DATA is always used as an output parameter of TPM2_Create() and TPM2_CreatePrimary()
 *     &creationHash,
 *     &creationTicket,
 *     &rspAuthsArray
 *     );
 * if (err) {
 *     return;
 * }
 * printf("creationData.t.size = %d\n", creationData.t.size);  // 由 TPM 输出的 creationData.t.size 正常情况应该大于 0
 * ```
 *
 * @see TPMS_CREATION_DATA: 即 TPM2B_CREATION_DATA 的实际内容结构体
 *
 * @see Tss2_Sys_Create() / Tss2_Sys_CreatePrimary()
 *
 * @see Tss2_Sys_Load() / TPM2B_NAME
 *
 * @see [TPM-Rev-2.0-Part-2-Structures-01.38.pdf](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf) ,
 * Chapter 15.2
 * Table 213: Definition of TPM2B_CREATION_DATA Structure
 */
typedef union {
    struct  {
        UINT16 size;
        TPMS_CREATION_DATA creationData;
    } t;
    TPM2B b;
} TPM2B_CREATION_DATA;

/**
 * The addtional outside information field.
 *
 * TPM2B_DATA was used by Tss2_Sys_Create() / Tss2_Sys_CreatePrimary() as an input parameter.
 * And in the meanwhile, it will be then placed in TPM2B_CREATION_DATA/TPMS_CREATION_DATA of these API functions as an output field.
 * @note Only used to append outside informations to TPMS_CREATION_DATA before generating key names.
 *
 * ```
 * // Typical usage:
 * TPM2B_DATA outsideInfo;
 *
 * outsideInfo.t.size = 0;
 * // Or:
 * // outsideInfo.t.size = sizeof(TPMT_HA);
 * // TPM2B_NAME external = ...;
 * // memcpy(outsideInfo.t.buffer, external.t.name, sizeof(TPMT_HA));
 *
 * Tss2_Sys_Create(
 *     sysContext,
 *     parentHandle,
 *     &cmdAuthsArray,
 *     &inSensitive,
 *     &inPublic,
 *     &outsideInfo, // TPM2B_DATA is used as an input parameter of TPM2_Create() and TPM2_CreatePrimary()
 *     &creationPCR,
 *     &outPrivate,
 *     &outPublic,
 *     &creationData,
 *     &creationHash,
 *     &creationTicket,
 *     &rspAuthsArray
 *     );
 * TPM2B_DATA *out = &(creationData.outsideInfo);
 * printf("out->t.size = %d\n", out->t.size);
 * ```
 *
 * @note Both TPM2B_DATA and TPM2B_NAME are wrapper structures for TPMT_HA.
 * @see TPMT_HA
 * @see Tss2_Sys_Create() / Tss2_Sys_CreatePrimary()
 * @see TPMS_CREATION_DATA / TPM2B_CREATION_DATA
 */
typedef union {
    struct  {
        UINT16 size;
        BYTE buffer[sizeof(TPMT_HA)];
    } t;
    TPM2B b;
} TPM2B_DATA;

/**
 * RSA 私钥
 *
 * @note 存储 RSA 私钥和公钥的结构体分别是 TPM2B_PRIVATE_KEY_RSA 和 TPM2B_PUBLIC_KEY_RSA
 * @details
 * 通常 RSA 私钥的长度应为公钥长度的一半.
 * @see RSA 公钥: TPM2B_PUBLIC_KEY_RSA
 */
typedef union {
    struct {
        UINT16 size; ///< 取值范围 (0, MAX_RSA_KEY_BYTES/2] 字节
        BYTE buffer[MAX_RSA_KEY_BYTES/2];
    } t;
    TPM2B b;
} TPM2B_PRIVATE_KEY_RSA;

/**
 * RSA 公钥
 *
 * @note 存储 RSA 私钥和公钥的结构体分别是 TPM2B_PRIVATE_KEY_RSA 和 TPM2B_PUBLIC_KEY_RSA
 * @details
 * 通常 RSA 公钥长度是私钥长度的两倍.
 * @see RSA 公钥最大长度: MAX_RSA_KEY_BITS / MAX_RSA_KEY_BYTES
 * @see RSA 私钥: TPM2B_PRIVATE_KEY_RSA
 */
typedef union {
    struct {
        UINT16 size; ///< 取值范围 (0, MAX_RSA_KEY_BYTES] 字节
        BYTE buffer[MAX_RSA_KEY_BYTES];
    } t;
    TPM2B b;
} TPM2B_PUBLIC_KEY_RSA;

/**
 * ECC 密钥椭圆曲线方程参数(私钥)
 *
 * @details
 * 用于存储椭圆曲线方程参数(另外, 此结构体兼用于存储曲线方程公钥坐标点中 x 或 y 值)
 *
 * @see 椭圆曲线方程参数(私钥)最大长度: MAX_ECC_KEY_BITS / MAX_ECC_KEY_BYTES
 * @see 椭圆曲线坐标点(公钥): TPM2B_ECC_POINT
 */
typedef union {
    struct {
        UINT16 size; ///< 取值范围 (0, MAX_ECC_KEY_BYTES] 字节
        BYTE buffer[MAX_ECC_KEY_BYTES];
    } t;
    TPM2B b;
} TPM2B_ECC_PARAMETER;

/**
 * ECC 密钥椭圆曲线坐标点(公钥)
 *
 * @details
 * Just a TPM2B_* wrapper layer of TPMS_ECC_POINT.
 *
 * @see 椭圆曲线坐标点: TPMS_ECC_POINT
 * @see 椭圆曲线方程参数(私钥): TPM2B_ECC_PARAMETER
 */
typedef union {
    struct {
        UINT16 size;
        TPMS_ECC_POINT point;
    } t;
    TPM2B b;
} TPM2B_ECC_POINT;

/**
 * 对称密钥
 *
 * @see 对称密钥最大长度: MAX_SYM_KEY_BITS / MAX_SYM_KEY_BYTES
 */
typedef union {
    struct {
        UINT16 size; ///< 取值范围 (0, MAX_SYM_KEY_BYTES] 字节
        BYTE buffer[MAX_SYM_KEY_BYTES];
    } t;
    TPM2B b;
} TPM2B_SYM_KEY;

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

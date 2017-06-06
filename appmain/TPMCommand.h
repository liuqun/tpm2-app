/* encoding: utf-8 */
/// @file TPMCommand.h
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.
#ifndef TPM_COMMAND_H_
#define TPM_COMMAND_H_

#include <sapi/tpm20.h>

#ifdef __cplusplus

/// @class TPMCommand
/// 作为所有 TPM 命令对象的抽象基类
class TPMCommand
{
public:
    struct In *m_in;
    struct Out *m_out;
public:
    int m_cmdAuthsCount; ///< 记录命令帧携带的 AuthValue 个数, 取值范围: [0,3]
    int m_rspAuthsCount; ///< 记录应答帧携带的 AuthValue 个数, 初始值应为 0, 执行完 unpackRspPacket() 之后会更新
    TPMS_AUTH_COMMAND m_sendAuthValues[3];
    TPMS_AUTH_RESPONSE m_fetchAuthResponse[3];
public:
    TPMCommand();
    virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
    virtual void unpackRspPacket(TSS2_SYS_CONTEXT *ctx);
    virtual ~TPMCommand();
    /** 指定授权方式(通过哪种会话进行授权校验) */
    virtual void configAuthSession(
            TPMI_SH_AUTH_SESSION authSessionHandle=TPM_RS_PW ///< 会话句柄, 可选取值包括: 明文密码授权会话句柄 TPM_RS_PW, 其他 HMAC/Policy 会话句柄
            );
    /** 指定指定授权访问密码或授权值(一般是指 TPM 密钥树父节点的访问密码) */
    virtual void configAuthPassword(
            const void *password, ///< 句柄授权数据
            UINT16 length ///< 授权数据长度(单位: 字节)
            );
    /** 擦除临时缓存的密码 */
    virtual void eraseCachedAuthPassword();
};

/// @namespace TPMCommands
/// @brief 盛放各种 TPM 命令对象的命名空间.
namespace TPMCommands
/// @see 用法参见相应目录下的 example 示例程序
{

/// 开机
class Startup: public TPMCommand
{
public:
    Startup();
    void enbleRestoreSavedState();
    void disableRestoreSavedState();
    virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
    virtual ~Startup();
};

/// 关机
class Shutdown: public TPMCommand
{
public:
    Shutdown();
    void enbleRestoreSavedState();
    void disableRestoreSavedState();
    virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
    virtual ~Shutdown();
};

/// 哈希计算命令
class Hash: public TPMCommand
/// @details
/// 调用 TPM 模块的单桢 Hash 计算命令, 输出哈希校验和,
/// 输入数据不能超过 1024 字节.
/// @note 当输入数据总长超过 1024 字节时, 必须改用 HashSequenceStart 命令,
/// 将长数据分割为若干个小于 1024 字节的短包.
/// ```
/// // 用法示意(伪代码):
/// TPMCommands::Hash cmd;
/// cmd.configHashAlgorithmUsingSHA1();
/// cmd.configInputData("abc", strlen("abc"));
/// cmd.buildCmdPacket(sysContext);
/// Tss2_Sys_Execute(sysContext);
/// cmd.unpackRspPacket(sysContext);
/// const TPM2B_DIGEST& hashDigest = cmd.outHash();
/// // 预期输出结果
/// // "abc" 对应的 SHA1 输出值应该是 20 字节数据, 如下:
/// // 0xA9 0x99 0x3E 0x36 0x47 0x06 0x81 0x6A 0xBA 0x3E
/// // 0x25 0x71 0x78 0x50 0xC2 0x6C 0x9C 0xD0 0xD8 0x9D
/// ```
{
public:
    Hash();
    virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
    virtual void unpackRspPacket(TSS2_SYS_CONTEXT *ctx);
    virtual ~Hash();
    /** 指定要使用哈希算法为 SHA1 */
    void configHashAlgorithmUsingSHA1();
    /** 指定要使用哈希算法为 SHA256 */
    void configHashAlgorithmUsingSHA256();
    /** 指定要使用哈希算法为 SHA384 */
    void configHashAlgorithmUsingSHA384();
    /**
     * 指定输入数据
     */
    void configInputData(const void *data, ///< 输入数据
            UINT16 length ///< 输入数据的总字节数, 取值范围 [0, 1024] 字节
            );
    /** 擦除临时缓存的输入数据 */
    void eraseCachedInputData();
    /**
     * 输出哈希计算的结果, 即摘要值
     */
    const TPM2B_DIGEST& outHash();
    /**
     * 输出相应的 ticket 值作为辅助数据.
     *
     * 后续执行签名等操作时需要该 ticket 值作为依据.
     */
    const TPMT_TK_HASHCHECK& outValidationTicket();
};

/// 新建授权会话命令
class StartAuthSession: public TPMCommand
/// 授权会话类型可以是 HMAC 会话或 Policy 会话.
/// 如果用户未指定类型, 则默认创建一个新的 HMAC 授权会话
{
public:
    StartAuthSession();
    virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
    virtual void unpackRspPacket(TSS2_SYS_CONTEXT *ctx);
    virtual ~StartAuthSession();
    /** 设置要创建授权会话类型: HMAC 授权会话 */
    void configSessionTypeAsHMACSession();
    /** 设置要创建授权会话类型: Policy 授权会话 */
    void configSessionTypeAsPolicySession();
    /** 设置新会话加密选项: 设置 salt 值并指定 TPM 解读该 salt 值时所需使用的密钥句柄 */
    void configEncryptedSaltAlongWithItsDecryptKey(UINT16 saltSize, void *encryptedSaltValue, TPM_HANDLE decryptKey);
    /** 设置新会话加密选项: 通过绑定某个 Entity 对象(密钥或 NV Index)为该会话指定的访问授权值, 即访问密码 */
    void configBindEntity(TPM_HANDLE entityHandle);
    /** 设置新会话的第一个 nonce 值(即 nonceCaller, 用于抵抗录音重放攻击) */
    void configNonceCaller(UINT16 nonceSize, void *nonceValue);
    /** 输出创建的会话句柄 */
    TPMI_SH_AUTH_SESSION outSessionHandle();
    /** 输出 TPM 返回的 Nonce 随机数(用于抵抗录音重放攻击) */
    const TPM2B_NONCE& outNonceTpm();
};

/// 清除指定的 HMAC 授权会话(或 policy 授权会话), 并释放资源.
class FlushAuthSession: public TPMCommand
{
public:
    FlushAuthSession();
    virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
    virtual ~FlushAuthSession();
    /** 指定要清除哪个授权会话 */
    void configSessionHandleToFlushAway(
            TPMI_SH_AUTH_SESSION sessionHandle ///< 授权会话句柄
            );
};

/// 清除指定 TPM 密钥节点, 并释放资源
class FlushLoadedKeyNode: public TPMCommand
{
public:
    FlushLoadedKeyNode();
    virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
    virtual ~FlushLoadedKeyNode();
    /** 指定要清除哪个密钥节点 */
    void configKeyNodeToFlushAway(
            TPM_HANDLE keyHandle ///< 密钥节点句柄
            );
};

/// 调用TPM 密钥创建命令 Tss2_Sys_CreatePrimary() 创建一个新的密钥树主节点
class CreatePrimary: public TPMCommand
{
public:
    CreatePrimary();
    virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
    virtual void unpackRspPacket(TSS2_SYS_CONTEXT *ctx);
    ~CreatePrimary();
    /**
     * 指定新的密钥树的放置位置
     *
     * 该函数指定新创建的密钥树主节点应位于哪个位置, 为了能够访问相应的位置句柄,
     * 调用该函数之后应再调用 TPMCommand::configAuthSession() TPMCommand::configAuthPassword() 等函数填写具体授权信息
     *
     * @param hierarchy 可选值包括:
     * - 0x40000007: TPM_RH_NULL
     * - 0x40000001: TPM_RH_OWNER
     * - 0x4000000C: TPM_RH_PLATFORM
     * - 0x4000000B: TPM_RH_ENDORSEMENT
     */
    void configAuthHierarchy(TPMI_RH_HIERARCHY hierarchy=TPM_RH_NULL);
    /**
     * 指定新密钥的访问授权密码和额外的敏感数据
     *
     * @param keyAuthValue 为即将创建的新密钥节点指定一个授权密码
     * @param size 授权值字节数, 可以等于 0
     * @param extraSensitiveData 当 extraDataSize == 0 时, 该指针将被忽略
     * @param extraDataSize 可以等于 0
     *
     * @see eraseCachedKeySensitiveData()
     */
    void configKeySensitiveData(
            /** 指定子节点的授权值 */
            const void *keyAuthValue,
            UINT16 size,
            /** 附加一些额外的初始值用于创建密钥 */
            const void *extraSensitiveData,
            UINT16 extraDataSize // 附加敏感数据的长度, 取值范围>=0
            );
    /**
     * 擦除已缓存的密钥敏感数据
     *
     * 擦除成员函数configKeySensitiveData()中指定的节点授权访问密+额外的敏感数据
     * @see configKeySensitiveData()
     */
    void eraseCachedKeySensitiveData();
    /**
     * 指定生成密钥树节点名称时采用哈希算法
     *
     * 注意请区别密钥节点名称哈希算法和 HMAC 之中的哈希算法, 两者是无关的
     *
     * @param nameAlg 哈希算法, 备选值包括:
     * - 0x0004 TPM_ALG_SHA1
     * - 0x000B TPM_ALG_SHA256
     * - 0x000C TPM_ALG_SHA384
     * - 0x000D TPM_ALG_SHA512
     * - 0x0012 TPM_ALG_SM3_256
     * - 0x0010 TPM_ALG_NULL (表示不进行哈希)
     */
    void configKeyNameAlg(TPMI_ALG_HASH nameAlg=TPM_ALG_SHA1);
    /** 指定密钥的公开数据(按TPM2B_PUBLIC格式指定) */
    void configPublicData(
            const TPM2B_PUBLIC& inPublic ///< 引用公开数据, 按 TPM2B_PUBLIC 数据结构输入
            );
    /** 指定密钥的公开数据(按TPMT_PUBLIC格式指定) */
    void configPublicData(
            const TPMT_PUBLIC& publicArea ///< 引用公开数据, 按 TPMT_PUBLIC 数据结构输入
            );
    /** 输出密钥的句柄 */
    TPM_HANDLE& outObjectHandle();
    /**
     * 输出密钥的私钥相关数据
     * @see _PRIVATE / TPM2B_PRIVATE
     * @see TPMU_SENSITIVE_COMPOSITE 是 TPM 存储私钥的数据格式
     * @see TPMT_SENSITIVE / TPM2B_SENSITIVE
     */
    TPM2B_PRIVATE& outPrivate();
    /**
     * 输出密钥的公开数据
     * @see TPMT_PUBLIC / TPM2B_PUBLIC
     */
    TPM2B_PUBLIC& outPublic();
    /**
     * 输出用于证明该密钥是由 TPM 模块创建的 ticket 结构体
     * @see TPMT_TK_CREATION
     */
    TPMT_TK_CREATION& outCreationTicket();
    /**
     * 输出 TPM 模块创建密钥数据和当时的环境状态记录
     * @see TPM2B_CREATION_DATA
     */
    TPM2B_CREATION_DATA& outCreationData();
    /** 输出 TPM2B_CREATION_DATA 结构体的哈希值      */
    TPM2B_DIGEST& outCreationHash();
    /** 输出新节点的节点名 */
    const TPM2B_NAME& outName();
};

/// TPM 密钥创建命令
class Create: public TPMCommand
/// @details
/// 创建一个普通密钥, 必须设置详细参数指定该密钥的类型
{
public:
    Create();
    virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
    virtual void unpackRspPacket(TSS2_SYS_CONTEXT *ctx);
    virtual ~Create();
    /** 指定通过密钥树中哪个父节点进行授权校验 */
    void configAuthParent(TPMI_DH_OBJECT parentHandle);
    /**
     * 指定新密钥的访问授权密码和额外的敏感数据
     *
     * @param keyAuthValue 为即将创建的新密钥节点指定一个授权密码
     * @param size 授权值字节数, 可以等于 0
     * @param extraSensitiveData 当 extraDataSize == 0 时, 该指针将被忽略
     * @param extraDataSize 可以等于 0
     *
     * @see eraseCachedKeySensitiveData()
     */
    void configKeySensitiveData(
            /** 指定子节点的授权值 */
            const void *keyAuthValue,
            UINT16 size,
            /** 附加一些额外的初始值用于创建密钥 */
            const void *extraSensitiveData,
            UINT16 extraDataSize // 附加敏感数据的长度, 取值范围>=0
            );
    /**
     * 擦除已缓存的密钥敏感数据
     *
     * 擦除成员函数configKeySensitiveData()中指定的节点授权访问密+额外的敏感数据
     * @see configKeySensitiveData()
     */
    void eraseCachedKeySensitiveData();
    /**
     * 指定生成密钥树节点名称时采用哈希算法
     *
     * 注意请区别密钥节点名称哈希算法和 HMAC 之中的哈希算法, 两者是无关的
     *
     * @param nameAlg 哈希算法, 备选值包括:
     * - 0x0004 TPM_ALG_SHA1
     * - 0x000B TPM_ALG_SHA256
     * - 0x000C TPM_ALG_SHA384
     * - 0x000D TPM_ALG_SHA512
     * - 0x0012 TPM_ALG_SM3_256
     * - 0x0010 TPM_ALG_NULL (表示不进行哈希)
     */
    void configKeyNameAlg(TPMI_ALG_HASH nameAlg=TPM_ALG_SHA1);
    /** 指定密钥的公开数据 */
    void configPublicData(
            const TPM2B_PUBLIC& inPublic ///< 引用公开数据数据结构体
            );
    /**
     * 输出密钥的私钥相关数据
     * @see _PRIVATE / TPM2B_PRIVATE
     * @see TPMU_SENSITIVE_COMPOSITE 是 TPM 存储私钥的数据格式
     * @see TPMT_SENSITIVE / TPM2B_SENSITIVE
     */
    TPM2B_PRIVATE& outPrivate();
    /**
     * 输出密钥的公开数据
     * @see TPMT_PUBLIC / TPM2B_PUBLIC
     */
    TPM2B_PUBLIC& outPublic();
    /**
     * 输出用于证明该密钥是由 TPM 模块创建的 ticket 结构体
     * @see TPMT_TK_CREATION
     */
    TPMT_TK_CREATION& outCreationTicket();
    /**
     * 输出 TPM 模块创建密钥数据和当时的环境状态记录
     * @see TPM2B_CREATION_DATA
     */
    TPM2B_CREATION_DATA& outCreationData();
    /**
     * 输出 TPM2B_CREATION_DATA 结构体的哈希值
     */
    TPM2B_DIGEST& outCreationHash();
};

/// HMAC 密钥创建命令
class HMACKeyCreate: public Create
/// @details
/// 创建一个用于 HMAC 校验的 keyed hash 密钥
/// ```
/// // 用法示意(伪代码):
/// TPMCommands::HMACKeyCreate create;
///
/// create.configAuthParent(parent);
/// create.configAuthSession(TPM_RS_PW);
/// create.configAuthPassword(parentPassword, strlen(parentPassword));
/// create.configKeyNameAlg(TPM_ALG_SHA1);
/// create.configKeySensitiveData(nodePassword, strlen(nodePassword), "", strlen(""));
/// create.configKeyParameters(TPM_ALG_SHA1);
/// create.buildCmdPacket(sysContext);
/// Tss2_Sys_Execute(sysContext);
/// create.unpackRspPacket(sysContext);
/// TPM2B_PRIVATE& priv = create.outPrivate();
/// TPM2B_PUBLIC& pub = create.outPublic();
/// ```
/// @see TPMCommands::Load 下一步调用 Load 命令时会用到 outPrivate() 和 outPublic() 输出的数据
{
public:
    HMACKeyCreate();
    /**
     * 配置该密钥为一个 HMAC KeyedHash 密钥, 指定密钥本身要使用的哈希算法
     *
     * @param hashAlg 备选值包括:
     * - 0x0004 TPM_ALG_SHA1
     * - 0x000B TPM_ALG_SHA256
     * - 0x000C TPM_ALG_SHA384
     * - 0x000D TPM_ALG_SHA512
     * - 0x0012 TPM_ALG_SM3_256
     * - 0x0010 TPM_ALG_NULL (表示不进行哈希)
     */
    void configHMACKeyParameters(TPMI_ALG_HASH hashAlg);
};

/// KeyedHash XOR 密钥创建命令
class KeyedHashXORKeyCreate: public Create
/// @details 创建一个用于进行 XOR 计算的 keyed hash 密钥
{
public:
    KeyedHashXORKeyCreate();
    /**
     * 配置该密钥为一个 XOR KeyedHash 密钥, 指定密钥本身要使用的哈希算法和 KDF 密钥派生算法
     *
     * @param hashAlg 备选值包括:
     * - 0x0004 TPM_ALG_SHA1
     * - 0x000B TPM_ALG_SHA256
     * - 0x000C TPM_ALG_SHA384
     * - 0x000D TPM_ALG_SHA512
     * - 0x0012 TPM_ALG_SM3_256
     * - 0x0010 TPM_ALG_NULL (表示不进行哈希)
     * @param kdf 密钥衍生算法,  备选值包括:
     * - 0x0022 TPM_ALG_KDF1_SP800_108
     * - 0x0020 TPM_ALG_KDF1_SP800_56A
     */
    void configKeyedHashXORKeyParameters(TPMI_ALG_HASH hashAlg, TPMI_ALG_KDF kdf=TPM_ALG_KDF1_SP800_108);
};

/// XOR 对称密钥创建命令
class SymmetricXORKeyCreate: public Create
/// @details 创建一个用于进行 XOR 计算的 keyed hash 密钥
{
public:
    SymmetricXORKeyCreate();
    /**
     * 配置该密钥为一个 XOR 对称密钥, 指定密钥本身要使用的哈希算法和 KDF 密钥派生算法
     *
     * @param hashAlg 备选值包括:
     * - 0x0004 TPM_ALG_SHA1
     * - 0x000B TPM_ALG_SHA256
     * - 0x000C TPM_ALG_SHA384
     * - 0x000D TPM_ALG_SHA512
     * - 0x0012 TPM_ALG_SM3_256
     * @note TPM 不允许设置 hashAlg 为 0x0010 TPM_ALG_NULL
     */
    void configSymmetricXORKeyParameters(TPMI_ALG_HASH hashAlg);
};

/// 加载命令
class Load: public TPMCommand
/// @details
/// 加载一个密钥或一个自定义 Object 对象到 TPM 的密钥节点插槽
/// ```
/// // 通常 Load 命令要配合前一条的 Create 命令一起使用
/// TPMCommands::HMACKeyCreate create;
/// TPMCommands::Load load;
///
/// create.configAuthParent(parent);
/// create.configAuthSession(TPM_RS_PW);
/// create.configAuthPassword(parentPassword, strlen(parentPassword));
/// create.configKeyNameAlg(TPM_ALG_SHA1);
/// create.configKeySensitiveData(nodePassword, strlen(nodePassword), "", strlen(""));
/// create.configKeyTypeAsHMACKey(TPM_ALG_SHA1);
/// create.buildCmdPacket(sysContext);
/// Tss2_Sys_Execute(sysContext);
/// create.unpackRspPacket(sysContext);
///
/// // Load 命令用法示例如下(伪代码):
/// load.configAuthParent(parent);
/// load.configAuthSession(TPM_RS_PW);
/// load.configAuthPassword(parentPassword, strlen(parentPassword));
/// load.configPrivateData(create.outPrivate());
/// load.configPublicData(create.outPublic());
/// load.buildCmdPacket(sysContext);
/// Tss2_Sys_Execute(sysContext);
/// load.unpackRspPacket(sysContext);
/// TPMI_OBJECT handle = load.outObjectHandle();
/// TPM2B_NAME& name = load.outName();
/// ```
{
public:
    Load();
    virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
    virtual void unpackRspPacket(TSS2_SYS_CONTEXT *ctx);
    virtual ~Load();
    /** 指定通过密钥树中哪个父节点进行授权校验 */
    void configAuthParent(TPMI_DH_OBJECT parentHandle);
    /** 指定授权方式(通过哪种会话进行授权校验) */
    void configAuthSession(
            TPMI_SH_AUTH_SESSION authSessionHandle=TPM_RS_PW ///< 会话句柄, 可选取值包括: 明文密码授权会话句柄 TPM_RS_PW, 其他 HMAC/Policy 会话句柄
            );
    /** 指定指定授权访问密码或授权值(一般是指 TPM 密钥树父节点的访问密码) */
    void configAuthPassword(
            const void *password, ///< 句柄授权数据
            UINT16 length ///< 授权数据长度(单位: 字节)
            );
    /** 擦除临时缓存的密码 */
    void eraseCachedAuthPassword();
    /** 指定要加载的密钥的私钥数据 */
    void configPrivateData(
            const TPM2B_PRIVATE& inPrivate ///< 引用已有的私钥数据结构
            );
    /** 指定要加载的密钥的公开数据 */
    void configPublicData(
            const TPM2B_PUBLIC& inPublic ///< 引用已有的公开数据
            );
    /** 返回新密钥节点的句柄 */
    TPM_HANDLE outObjectHandle();
    /**
     * 输出新创建的密钥名
     * @see TPMU_NAME / TPM2B_NAME
     * @see TPMT_HA
     */
    const TPM2B_NAME& outName();
    /**
     * 擦除临时缓存的输出数据, 会同时清零其他成员函数返回的只读数据块的值, 均为非敏感数据
     */
    void eraseCachedOutputData();
};

/// 读取密钥的公开数据
class ReadPublic: public TPMCommand
/// @details
/// 已知密钥句柄, 读取密钥的公开数据. 其中包括非对称密钥的公钥部分和 TPM 密钥树中相应的节点名等
/// ```
/// // 用法示意(伪代码):
/// TPMCommands::ReadPublic cmd;
///
/// cmd.configObject(handle);
/// cmd.buildCmdPacket(sysContext);
/// Tss2_Sys_Execute(sysContext);
/// cmd.unpackRspPacket(sysContext);
/// const TPMT_PUBLIC& pub = cmd.outPublicArea();
/// const TPM2B_NAME& name = cmd.outName();
/// const TPM2B_NAME& qn = cmd.outQualifiedName();
/// // 注意请把输出变量定义为 const 型的 C++ 变量引用, 否则编译器会警告不允许类型转换时丢弃 const
/// ```
{
public:
    ReadPublic();
    virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
    virtual void unpackRspPacket(TSS2_SYS_CONTEXT *ctx);
    virtual ~ReadPublic();
    /** 指定要查询的对象 */
    void configObject(TPMI_DH_OBJECT objectHandle);
    /**
     * 输出查询结果中的 NV 公开信息区域
     * @see TPMT_PUBLIC / TPM2B_PUBLIC
     */
    const TPMT_PUBLIC& outPublicArea();
    /**
     * 输出查询结果中的 NV 公开信息区域
     * @see TPMT_PUBLIC / TPM2B_PUBLIC
     * @see ValueFromTPM2B() 拆解 TPM2B_* 数据块
     */
    const TPM2B_PUBLIC& outPublic();
    /**
     * 输出查询结果对象名
     * @see TPMU_NAME / TPM2B_NAME
     * @see TPMT_HA
     */
    const TPM2B_NAME& outName();
    /**
     * 输出查询结果对象QN名
     * @see TPMU_NAME / TPM2B_NAME
     * @see TPMT_HA
     */
    const TPM2B_NAME& outQualifiedName();
    /** 擦除所有临时缓存的输出数据, 前两个成员函数的返回值也会被清零 */
    void eraseCachedOutputData();
};

namespace NV
/// @brief 盛放与非易失性存储器相关的读写命令的命名空间.
{

    /// 定义非易失性存储空间
    class DefineSpace: public TPMCommand
    /// @see Tss2_Sys_NV_DefineSpace()
    {
    public:
        DefineSpace();
        virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
        virtual ~DefineSpace();
        void configNVIndex(TPMI_RH_NV_INDEX index);
        void configNVIndexDataSize(UINT16 dataSize);
        void configCreatorAsPlatform();
        void configCreatorAsOwner();
        void configNVIndexAuthPassword(
                const void *authPassword, ///< 密码
                UINT16 len ///< 密码长度
                );
        /**
         * 擦除之前配置的密码
         *
         * @details 程序退出前通过析构函数自动调用本函数, 擦除 C++ 对象运行时内存中残留的密码数据
         */
        void eraseCachedNVIndexAuthPassword();
    };

    /// 读取 NV 非敏感数据
    class ReadPublic: public TPMCommand
    /// @details
    /// ```
    /// // 用法示意(伪代码):
    /// TPMCommands::NV::ReadPublic cmd;
    ///
    /// cmd.configNVIndex((TPMI_RH_NV_INDEX) 0x015000020); // 假定之前已经创建了 NV Index 0x015000020
    /// cmd.buildCmdPacket(sysContext);
    /// Tss2_Sys_Execute(sysContext);
    /// cmd.unpackRspPacket(sysContext);
    /// TPMS_NV_PUBLIC& pub = cmd.outNVPublicArea();
    /// TPM2B_NAME& name = cmd.outNVName();
    /// TPMU_NAME& nameValue = ValueFromTPM2B(name);
    /// ```
    {
    public:
        ReadPublic();
        virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
        virtual void unpackRspPacket(TSS2_SYS_CONTEXT *ctx);
        virtual ~ReadPublic();
        /** 指定要访问的 NV Index */
        void configNVIndex(TPMI_RH_NV_INDEX index);
        /**
         * 输出查询结果中的 NV 公开信息区域
         * @see TPMS_NV_PUBLIC / TPM2B_NV_PUBLIC
         */
        const TPMS_NV_PUBLIC& outNVPublicArea();
        /**
         * 输出查询结果中的 NV 对象名
         * @see TPMU_NAME / TPM2B_NAME
         * @see TPMT_HA
         */
        const TPM2B_NAME& outNVName();
        /** 擦除所有临时缓存的输出数据, 前两个成员函数的返回值也会被清零 */
        void eraseCachedOutputData();
    };

    /// 写入 NV 数据
    class Write: public TPMCommand
    {
    public:
        Write();
        virtual ~Write();
        virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
        virtual void unpackRspPacket(TSS2_SYS_CONTEXT *ctx);
        /** 指定要写入的 NV Index 及写入位置起始偏移量 */
        void configNVIndex(
                TPMI_RH_NV_INDEX index, ///< Index
                UINT16 offset ///< 起始偏移量
                );
        /** 指定要写入的数据 */
        void configInputData(
                const void *data, ///< 数据块指针
                UINT16 length ///< 数据长度(单位: 字节), 取值范围: [0, MAX_NV_BUFFER_SIZE]
                );
        /** 擦除临时缓存的输入数据 */
        void eraseCachedInputData();
        /** 指定授权方式会话 */
        void configNVIndexAuthSession(
                TPMI_SH_AUTH_SESSION authSessionHandle=TPM_RS_PW ///< 会话句柄, 可选取值包括: 明文密码授权会话句柄 TPM_RS_PW, 其他 HMAC/Policy 会话句柄
                );
        /** 指定密码授权会话使用的密码 */
        void configNVIndexPassword(
                const void *password, ///< 句柄授权数据
                UINT16 length ///< 授权数据长度
                );
        /**
         * 擦除访问为了 NV Index 而临时缓存的密码
         *
         * @details 程序退出前析构函数将自动调用本函数, 擦除 C++ 对象运行时内存中残留的密码数据
         */
        void eraseCachedPassword();
    };

    /// 读取 NV 数据()
    class Read: public TPMCommand
    {
    public:
        Read();
        virtual ~Read();
        virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
        virtual void unpackRspPacket(TSS2_SYS_CONTEXT *ctx);
        /** 输出读取 NV 的最终结果 */
        const TPM2B& result();
        /**
         * 按 TPM2B_MAX_NV_BUFFER 格式直接输出 NV 读取结果
         * @see MAX_NV_BUFFER_SIZE / TPM2B_MAX_NV_BUFFER
         */
        const TPM2B_MAX_NV_BUFFER& outData();
        /** 指定要读的 NV Index 以及起始偏移量和数据字节数 */
        void configNVIndex(
                TPMI_RH_NV_INDEX index, ///< Index
                UINT16 dataSize, ///< 数据字节数
                UINT16 offset ///< 起始偏移量
                );
        /** 指定授权方式会话 */
        void configNVIndexAuthSession(
                TPMI_SH_AUTH_SESSION authSessionHandle=TPM_RS_PW ///< 会话句柄, 可选取值包括: 明文密码授权会话句柄 TPM_RS_PW, 其他 HMAC/Policy 会话句柄
                );
        /** 指定密码授权会话使用的密码 */
        void configNVIndexPassword(
                const void *password, ///< 句柄授权数据
                UINT16 length ///< 授权数据长度
                );
        /**
         * 擦除访问为了 NV Index 而临时缓存的密码
         *
         * @details 程序退出前析构函数将自动调用本函数, 擦除 C++ 对象运行时内存中残留的密码数据
         */
        void eraseCachedPassword();
        /**
         * 擦除临时缓存的 NV Index 数据
         *
         * @details 程序退出前析构函数将自动调用本函数, 擦除 C++ 对象运行时内存中残留的密码数据
         */
        void eraseCachedOutputData();
    };

}// end of namespace NV
} // end of namecpace TPMCommands
#endif//__cplusplus

// ============================================================================
// 提供一组 TPM2B_* 数据转换工具(C++ 接口)
// ============================================================================

#ifdef __cplusplus

/** TPM2B_ENCRYPTED_SECRET--TPMU_ENCRYPTED_SECRET 数据类型转换函数 */
const TPMU_ENCRYPTED_SECRET& ValueFromTPM2B(const TPM2B_ENCRYPTED_SECRET& secret);

/** TPM2B_NAME--TPMU_NAME 数据类型转换函数 */
const TPMU_NAME& ValueFromTPM2B(const TPM2B_NAME& name);

/** TPM2B--BYTE 数据类型转换函数 */
const BYTE *ValueFromTPM2B(const TPM2B& data);

/** TPM2B_MAX_NV_BUFFER--BYTE 数据类型转换函数 */
const BYTE *ValueFromTPM2B(const TPM2B_MAX_NV_BUFFER& block);

#endif//__cplusplus

// ============================================================================
// 提供一组 TPM2B_* 数据转换工具(C 接口)
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif//__cplusplus

/** TPM2B_ENCRYPTED_SECRET--TPMU_ENCRYPTED_SECRET 数据类型转换函数 */
const TPMU_ENCRYPTED_SECRET *TPMU_ENCRYPTED_SECRET__From__TPM2B_ENCRYPTED_SECRET(const TPM2B_ENCRYPTED_SECRET *pSecret);

/** TPM2B_NAME--TPMU_NAME 数据类型转换函数 */
const TPMU_NAME *TPMU_NAME__From__TPM2B_NAME(const TPM2B_NAME *pName);

/** TPM2B--BYTE 数据类型转换函数 */
const BYTE *BYTE__From__TPM2B(const TPM2B *pData);

/** TPM2B_MAX_NV_BUFFER--BYTE 数据类型转换函数 */
const BYTE *BYTE__From__TPM2B_MAX_NV_BUFFER(const TPM2B_MAX_NV_BUFFER *pBlock);

#ifdef __cplusplus
} // End of extern "C"
#endif//__cplusplus

#endif//TPM_COMMAND_H_

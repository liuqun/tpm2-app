/* encoding: utf-8 */
/// @file TPMCommand.h
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.
#ifndef TPM_COMMAND_H_
#define TPM_COMMAND_H_

#include <sapi/tpm20.h>

// ============================================================================
// 提供一组 TPM2B_* 数据转换工具(C++ 接口)
// ============================================================================

#ifdef __cplusplus

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

/** TPM2B_NAME--TPMU_NAME 数据类型转换函数 */
const TPMU_NAME *TPMU_NAME__From__TPM2B_NAME(const TPM2B_NAME *pName);

/** TPM2B--BYTE 数据类型转换函数 */
const BYTE *BYTE__From__TPM2B(const TPM2B *pData);

/** TPM2B_MAX_NV_BUFFER--BYTE 数据类型转换函数 */
const BYTE *BYTE__From__TPM2B_MAX_NV_BUFFER(const TPM2B_MAX_NV_BUFFER *pBlock);

#ifdef __cplusplus
} // End of extern "C"
#endif//__cplusplus

#ifdef __cplusplus

/// @class TPMCommand
/// 作为所有 TPM 命令对象的抽象基类
class TPMCommand
{
public:
    struct Parameters_In *m_in;
    struct Parameters_Out *m_out;
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

/// 加载命令
class Load: public TPMCommand
/// @details
/// 加载一个密钥或一个自定义 Object 对象到 TPM 的密钥节点插槽
/// ```
/// // 用法示意(伪代码):
/// TPMCommands::Load cmd;
///
/// cmd.configAuthParent(parent);
/// cmd.configAuthSession();
/// cmd.configAuthPassword();
/// cmd.configPrivateData();
/// cmd.configPublicData();
/// cmd.buildCmdPacket(sysContext);
/// Tss2_Sys_Execute(sysContext);
/// cmd.unpackRspPacket(sysContext);
/// TPMI_OBJECT handle = cmd.outObjectHandle();
/// TPM2B_NAME& name = cmd.outName();
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
            UINT16 length ///< 授权数据长度
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
/// const TPMS_PUBLIC& pub = cmd.resultPublicArea();
/// const TPM2B_NAME& name = cmd.resultName();
/// const TPM2B_NAME& qn = cmd.resultQualifiedName();
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
    const TPMT_PUBLIC& resultPublicArea();
    /**
     * 输出查询结果对象名
     * @see TPMU_NAME / TPM2B_NAME
     * @see TPMT_HA
     */
    const TPM2B_NAME& resultName();
    /**
     * 输出查询结果对象QN名
     * @see TPMU_NAME / TPM2B_NAME
     * @see TPMT_HA
     */
    const TPM2B_NAME& resultQualifiedName();
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
        void eraseNVIndexAuthPassword();
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
    /// TPMS_NV_PUBLIC& pub = cmd.resultNVPublicArea();
    /// TPM2B_NAME& name = cmd.resultNVName();
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
        const TPMS_NV_PUBLIC& resultNVPublicArea();
        /**
         * 输出查询结果中的 NV 对象名
         * @see TPMU_NAME / TPM2B_NAME
         * @see TPMT_HA
         */
        const TPM2B_NAME& resultNVName();
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

#endif//TPM_COMMAND_H_

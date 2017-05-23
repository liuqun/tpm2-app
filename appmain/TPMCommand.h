/* encoding: utf-8 */
/// @file TPMCommand.h
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.
#ifndef TPM_COMMAND_H_
#define TPM_COMMAND_H_

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
};

/// @namespace TPMCommands
/// @details 盛放各种 TPM 命令对象的命名空间.
/// @see 用法参见相应目录下的 example 示例程序
namespace TPMCommands {

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

/// 读取密钥(或自定义Object)非敏感数据
class ReadPublic: public TPMCommand
{
public:
    ReadPublic();
    virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
    virtual void unpackRspPacket(TSS2_SYS_CONTEXT *ctx);
    virtual ~ReadPublic();
};

/// @namespace NV
/// @details 盛放 NV 操作的命名空间.
namespace NV {

    /// 定义非易失性存储空间
    /// @see Tss2_Sys_NV_DefineSpace()
    class DefineSpace: public TPMCommand
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
    /// @see Tss2_Sys_NV_ReadPublic()
    class ReadPublic: public TPMCommand
    {
    public:
        ReadPublic();
        virtual void buildCmdPacket(TSS2_SYS_CONTEXT *ctx);
        virtual void unpackRspPacket(TSS2_SYS_CONTEXT *ctx);
        virtual ~ReadPublic();
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

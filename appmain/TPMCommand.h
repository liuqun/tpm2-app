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

} // end of namecpace TPMCommands
#endif//__cplusplus

#endif//TPM_COMMAND_H_

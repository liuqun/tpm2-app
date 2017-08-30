/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef CLIENT_H_
#define CLIENT_H_

#ifndef __cplusplus
#warning // Only C++ is supported. Please DON'T include this file from *.c!
#endif

#include <sapi/tpm20.h>
#include "TPMCommand.h"
#include "TSSContextInitializer.h"

#ifdef __cplusplus

/// TPM客户端
class Client
{
private:
    size_t m_sysContextSize;

public:
    TSS2_SYS_CONTEXT *m_sysContext; ///< 成员变量 m_sysContext (取代全局变量 sysContext, 降低耦合度).
    /** 构造函数 */
    Client();
    /** 客户端初始化 */
    void initialize(TSSContextInitializer& initializer);
    /** 析构函数 */
    virtual ~Client();
    /** 发送命令帧 */
    void sendCommand(
            TPMCommand& command ///< 输入参数. 此TPMCommand对象自带buildCmdPacket()组帧方法生成命令帧报文
            );
    /**
     * 取回应答帧
     *
     * @note 该函数放在每条sendCommand()之后被调用. 若没有发送过命令帧, 则无法取回的应答桢.
     * @note 若该函数执行成功, 返回的数据将被写入之前调用 sendCommand() 时指定的 command 对象.
     *
     * @throws TSS2_RC (可能遇到多种错误情况, 包括TSS层或TPM硬件返回的错误码) TODO: 此处需补充文档和样例代码帮助开发者处理不同的 TPM_RC/TSS2_RC 错误编码.
     */
    void fetchResponse(
            int32_t timeout=-1 ///< 超时选项. 默认使用负数表示阻塞等待, 直到服务器端应答或者发生其他严重错误
            );
    /** 发送命令帧并取回应答帧 */
    void sendCommandAndWaitUntilResponseIsFetched(
            TPMCommand& cmd ///< 输入参数. 此TPMCommand对象自带buildCmdPacket()组帧方法生成命令帧报文
            );

private:
    TPMCommand *m_pLastCommand; ///< 内部成员变量. m_pLastCommand总是指向之前最后一次调用sendCommand()成员函数时的关联的TPMCommand参数的内存地址
};

/// 对外定义C++包装器类
class WrapperClient
{
public:
    /** 依靠外部initializer对此伪调度器进行初始化 */
    virtual void initialize(TSSContextInitializer& initializer) = 0;
};

#endif // __cplusplus
#endif // CLIENT_H_

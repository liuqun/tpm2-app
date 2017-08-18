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

#ifdef __cplusplus

/// 上下文初始化工具抽象基类: 仅声明一个回调函数接口原型 initializerCallbackFunc(), 由她的子类去集成实现该接口.
class ClientContextInitializer {
public:
    /** 回调接口原型 */
    virtual void initializerCallbackFunc(TSS2_TCTI_CONTEXT *tctiContext, size_t tctiContextSize, TSS2_SYS_CONTEXT *sysContext, size_t sysContextSize);
};

/// TPM客户端
class Client
{
private:
    ClientContextInitializer *m_contextInitializer; ///<
    TSS2_TCTI_CONTEXT *m_tctiContext; ///< 成员变量 m_tctiContext (取代全局变量 tctiContext, 降低耦合度).
    size_t m_tctiContextSize;
    size_t m_sysContextSize;

public:
    TSS2_SYS_CONTEXT *m_sysContext; ///< 成员变量 m_sysContext (取代全局变量 sysContext, 降低耦合度).
    /** 构造函数 */
    Client();
    /** 析构函数 */
    virtual ~Client();
    /** 指定外部回调函数, 并使用该回调函数执行 TCTI / System API 上下文对象初始化 */
    void setContextInitializer(ClientContextInitializer& initializer);
    /**
     * 与TPM2.0设备或本地Simulator模拟器守护进程建立连接
     *
     * 之前指定的上下文初始化
     */
    void connect();
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
    /**
     * 切断与守护进程之间的通讯连接
     *
     * @details
     * 优雅地切断之前建立的任意 socket 连接(通常是与 TSS resource manager 守护进程之间的链接)
     * 底层调用 shutdown() 通知socket服务器端正常结束会话连接(connection), 然后调用 closesocket() 关闭本地套接字.
     */
    void disconnect();

private:
    TPMCommand *m_pLastCommand; ///< 内部成员变量. m_pLastCommand总是指向之前最后一次调用sendCommand()成员函数时的关联的TPMCommand参数的内存地址
};

/// 基于 TCP 套接字的 TCTI / System API 初始化工具
class SocketBasedClientContextInitializer: public ClientContextInitializer {
public:
    /** 构造函数 */
    SocketBasedClientContextInitializer(const char *hostname="127.0.0.1", uint16_t port=2321);
    /** 析构函数 */
    virtual ~SocketBasedClientContextInitializer();
    /** 回调接口 */
    virtual void initializerCallbackFunc(TSS2_TCTI_CONTEXT *, size_t, TSS2_SYS_CONTEXT *, size_t);
private:
    const char *m_hostname;
    uint16_t m_port;
};

/// 直接读写 /dev/tpm0 设备的 TCTI / System API 初始化工具
class DeviceBasedClientContextInitializer: public ClientContextInitializer {
public:
    /** 构造函数 */
    DeviceBasedClientContextInitializer(const char *device="/dev/tpm0");
    /** 析构函数 */
    virtual ~DeviceBasedClientContextInitializer();
    /** 回调接口 */
    virtual void initializerCallbackFunc(TSS2_TCTI_CONTEXT *, size_t, TSS2_SYS_CONTEXT *, size_t);
private:
    const char *m_device;
};

#endif // __cplusplus
#endif // CLIENT_H_

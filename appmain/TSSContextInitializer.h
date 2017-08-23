/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef TSS_CONTEXT_INITIALIZER_H_
#define TSS_CONTEXT_INITIALIZER_H_

#ifndef __cplusplus
#warning // Only C++ is supported. Please DON'T include this file from *.c!
#endif

#include <sapi/tpm20.h>

#ifdef __cplusplus

/// TSS 上下文初始化助手工具类
class TSSContextInitializer {
public:
    /// 构造函数
    TSSContextInitializer();

    /// 主动发起连接
    ///
    /// 可能连接到本地 TPM 硬件, 也可能连接到 TCP 2321 端口上运行的软件 TPM 模拟器
    /// (该接口必须由子类继承并 override)
    virtual void connect() = 0;

    /// 主动断开连接
    /// (该接口必须由子类继承并 override)
    virtual void disconnect() = 0;

    /// 回调函数接口:
    ///
    /// @param sysContext 指向预分配的空白内存空间.
    /// @param sysContextSize 空白内存空间的大小. 单位: 字节.
    void setupSysContext(TSS2_SYS_CONTEXT *sysContext, size_t sysContextSize);

protected:
    TSS2_TCTI_CONTEXT *m_tctiContext;
};



/// 基于 TCP 套接字的 TCTI / System API 初始化助手工具
class SocketBasedTSSContextInitializer: public TSSContextInitializer {
public:
    /// 构造函数
    SocketBasedTSSContextInitializer(const char *szHostname="127.0.0.1", unsigned short nPort=2321);
    /// 析构函数
    ~SocketBasedTSSContextInitializer();
    /// 连接到 TCP 2321 端口上运行的软件 TPM 模拟器
    void connect();
    /// 主动断开连接
    void disconnect();

private:
    const char *m_szHostname; ///< 主机名或主机IP地址
    unsigned short m_nPort; ///< TCP 端口号
    size_t m_tctiContextSize;
};


/// 直接读写 /dev/tpm0 设备的 TCTI / System API 初始化助手工具
class DeviceBasedTSSContextInitializer: public TSSContextInitializer {
public:
    /// 构造函数
    DeviceBasedTSSContextInitializer(const char *szDevice
            /* Unix / Linux 下默认的 TPM 设备名 */ = "/dev/tpm0"         ///< TPM 设备名
            );
    /// 析构函数
    ~DeviceBasedTSSContextInitializer();
    /// 连接到本地 TPM 硬件
    void connect();
    /// 主动断开连接
    void disconnect();

private:
    const char *m_szDevice; ///< TPM 设备名
    size_t m_tctiContextSize;
};

#endif // __cplusplus
#endif // TSS_CONTEXT_INITIALIZER_H_

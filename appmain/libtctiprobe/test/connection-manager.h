/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef CONNECTION_MANAGER_H_
#define CONNECTION_MANAGER_H_

#ifndef __cplusplus
#warning // Only C++ is supported. Please DON'T include this file from *.c!
#endif

#include <sapi/tpm20.h>

#ifdef __cplusplus

/// 连接管理器
class ConnectionManager {
public:
    /// 主动发起连接
    ///
    /// 可能连接到本地 TPM 硬件, 也可能连接到 TCP 2321 端口上运行的软件 TPM 模拟器
    /// (该接口必须由子类继承并 override)
    virtual void connect() = 0;

    /// 主动断开连接
    /// (该接口必须由子类继承并 override)
    virtual void disconnect() = 0;

    ///
    virtual void initializeSysContext(TSS2_SYS_CONTEXT *sys_context, size_t sys_context_size) = 0;
};


#include <stdexcept>

class ConnectionManagerError: public std::runtime_error {
public:
    explicit ConnectionManagerError(const std::string& msg);
};

#endif // __cplusplus
#endif // CONNECTION_MANAGER_H_

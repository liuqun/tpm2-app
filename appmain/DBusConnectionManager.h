/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef DBUS_CONNECTION_MANAGER_H_
#define DBUS_CONNECTION_MANAGER_H_

#ifndef __cplusplus
#warning // Only C++ is supported. Please DON'T include this file from *.c!
#endif

#include <sapi/tpm20.h>

#ifdef __cplusplus

#include "ConnectionManager.h"

/// 连接到 tpm2-abrmd DBus 守护进程的连接管理器
class DBusConnectionManager: public ConnectionManager {
public:
    /// 构造函数
    DBusConnectionManager();
    /// 析构函数
    ~DBusConnectionManager();
    /// 连接到 tpm2-abrmd DBus 守护进程
    void connect();
    /// 主动断开连接
    void disconnect();
    ///
    void initializeSysContext(TSS2_SYS_CONTEXT *sysContext, size_t contextSize);

private:
    TSS2_TCTI_CONTEXT *m_tctiContext;
    size_t m_tctiContextSize;
};

#endif // __cplusplus
#endif // DBUS_CONNECTION_MANAGER_H_

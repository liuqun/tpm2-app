/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef SOCKET_CONNECTION_MANAGER_H_
#define SOCKET_CONNECTION_MANAGER_H_

#ifndef __cplusplus
#warning // Only C++ is supported. Please DON'T include this file from *.c!
#endif

#include <sapi/tpm20.h>

#ifdef __cplusplus

#include "ConnectionManager.h"

/// Socket 连接管理器
class SocketConnectionManager: public ConnectionManager {
public:
    /// 构造函数
    SocketConnectionManager(const char *szHostname="127.0.0.1", unsigned short nPort=2321);
    /// 析构函数
    ~SocketConnectionManager();
    /// 连接到 TCP 2321 端口上运行的软件 TPM 模拟器
    void connect();
    /// 主动断开连接
    void disconnect();
    ///
    void initializeSysContext(TSS2_SYS_CONTEXT *sysContext, size_t contextSize);

private:
    const char *m_szHostname; ///< 主机名或主机IP地址
    unsigned short m_nPort; ///< TCP 端口号
    TSS2_TCTI_CONTEXT *m_tctiContext;
    size_t m_tctiContextSize;
};

#endif // __cplusplus
#endif // SOCKET_CONNECTION_MANAGER_H_

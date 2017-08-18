/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <cstdio>
#include <cstdlib> // malloc()/free()
#include <cassert> // assert()
#include <stdexcept>
using std::exception;
#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include <tcti/tcti_device.h>
#include "TPMCommand.h"
#include "Client.h"

/* 排版格式: 以下函数均使用4个空格缩进，不使用Tab缩进 */

static size_t GetSocketTctiContextSize() {
    TCTI_SOCKET_CONF emptyConf;
    size_t size;
    TSS2_RC err;

    err = InitSocketTcti(NULL, &size, &emptyConf, 0);
    if (err) {
        fprintf(stderr,
                "Error: Failed to fetch size of TSS2_TCTI_CONTEXT from libtcti-socket\n");
        fprintf(stderr, "(This error should NEVER happen)\n");
        return 0;
    }
    return size;
}

static size_t GetDeviceTctiContextSize() {
    TCTI_DEVICE_CONF emptyConf;
    size_t size;
    TSS2_RC err;

    err = InitDeviceTcti(NULL, &size, &emptyConf);
    if (err)
    {
        fprintf(stderr,
                "Error: Failed to fetch size of TSS2_TCTI_CONTEXT from libtcti-device\n");
        fprintf(stderr, "(This error should NEVER happen)\n");
        return 0;
    }
    return size;
}

static size_t GetMax(size_t a, size_t b) {
    size_t max;

    max = (a >= b)? a:b;
    return (max);
}

size_t GetMaxTctiContextSize() {
    size_t max;

    max = GetMax(GetDeviceTctiContextSize(), GetSocketTctiContextSize());
    return (max);
}

Client::Client() {
    m_tctiContextSize = GetMaxTctiContextSize();
    m_tctiContext = (TSS2_TCTI_CONTEXT *) malloc(m_tctiContextSize);
    assert(m_tctiContext);
    if (!m_tctiContext) {
        fprintf(stderr, "Error: malloc() failed to allocate dynamic memory\n");
        exit (EXIT_FAILURE);
    }
    memset(m_tctiContext, 0x00, m_tctiContextSize);

    m_sysContextSize = Tss2_Sys_GetContextSize(0);
    m_sysContext = (TSS2_SYS_CONTEXT *) malloc(m_sysContextSize);
    if (!m_sysContext)
    {
        fprintf(stderr, "Error: malloc() failed to allocate dynamic memory\n");
        exit (EXIT_FAILURE);
    }
    memset(m_sysContext, 0x00, m_sysContextSize);
    m_pLastCommand = NULL;
    m_contextInitializer = NULL;
}

Client::~Client() {
    /* 销毁 TCTI 上下文对象 */
    assert(m_tctiContext);
    free(m_tctiContext);

    /* 销毁 System API 上下文对象 */
    assert(m_sysContext);
    free(m_sysContext);
}

void Client::sendCommandAndWaitUntilResponseIsFetched(TPMCommand& cmd) {
    int timeout = TSS2_TCTI_TIMEOUT_BLOCK;
    try {
        sendCommand(cmd);
        m_pLastCommand = &cmd;
        fetchResponse(timeout);
    } catch (std::exception e) {
        // TODO: 处理发送命令桢或接收响应桢中可能遇到的异常情况, 例如响应超时等
    }
}

void Client::sendCommand(TPMCommand& cmd) {
    cmd.buildCmdPacket(m_sysContext); // 调用相应的 TSS 软件栈 Tss2_Sys_XXXX_Prepare() 函数

    // 异步发送命令帧
    TSS2_RC err = Tss2_Sys_ExecuteAsync(m_sysContext);
    if (err) {
        fprintf(stderr, "Error: Cannot send command packet: Tss2_Sys_ExecuteAsync() returns 0x%X\n", (int) err);
        // TODO: throw/raise an expection to the up level
    }
    m_pLastCommand = &cmd;
}

void Client::fetchResponse(int32_t timeout) {
    if (!m_pLastCommand) {
        fprintf(stderr, "Error: No response packet to fetch\n");
        // Note: throw/raise an expection to the up level
        const TSS2_RC AppError=(TSS2_APP_ERROR_LEVEL|TSS2_BASE_RC_BAD_SEQUENCE);
        throw AppError;
    }

    if (timeout < 0) {
        timeout = TSS2_TCTI_TIMEOUT_BLOCK;
    }
    TSS2_RC err = Tss2_Sys_ExecuteFinish(m_sysContext, timeout);
    if (err) {
        fprintf(stderr, "Error: Cannot fetch response packet: Tss2_Sys_ExecuteFinish() returns err = 0x%X\n", err);
        // TODO: throw/raise an expection to the up level
        throw err;
    }
    m_pLastCommand->unpackRspPacket(m_sysContext); // 调用相应的 TSS 软件栈 Tss2_Sys_XXXX_Complete() 函数
}

void Client::disconnect() {
    assert(m_sysContext);
    Tss2_Sys_Finalize(m_sysContext);

    assert(m_tctiContext);
    const TSS2_TCTI_CONTEXT_COMMON_CURRENT *ctx =
            (TSS2_TCTI_CONTEXT_COMMON_CURRENT *) m_tctiContext;
    if (!(ctx->finalize)) {
        return;
    }
    else if (ctx->version < 1) {
        return;
    }
    ctx->finalize(m_tctiContext);
}

void Client::connect() {
    assert(m_contextInitializer);
    m_contextInitializer->initializerCallbackFunc(m_tctiContext, m_tctiContextSize, m_sysContext, m_sysContextSize);
}

void Client::setContextInitializer(ClientContextInitializer& initializer) {
    m_contextInitializer = &initializer;
}

// 以下为 TCTI / System API 上下文初始化工具

// 回调函数原型 initializerCallbackFunc()
void ClientContextInitializer::initializerCallbackFunc(TSS2_TCTI_CONTEXT *tctiContext, size_t tctiContextSize, TSS2_SYS_CONTEXT *sysContext, size_t sysContextSize)
{
}

// 构造函数 SocketBasedClientContextInitializer()
SocketBasedClientContextInitializer::SocketBasedClientContextInitializer(const char *hostname, uint16_t port)
{
    if (!hostname)
    {
        hostname = "127.0.0.1";
    }
    m_hostname = hostname;
    m_port = port;
}

// 析构函数 ~SocketBasedClientContextInitializer()
SocketBasedClientContextInitializer::~SocketBasedClientContextInitializer()
{
}

// 回调函数 initializerCallbackFunc()
void SocketBasedClientContextInitializer::initializerCallbackFunc(TSS2_TCTI_CONTEXT *tctiContext, size_t tctiContextSize, TSS2_SYS_CONTEXT *sysContext, size_t sysContextSize)
{
    TCTI_SOCKET_CONF conf;
    conf.hostname = (const char *) m_hostname;
    conf.port = m_port;
    conf.logCallback = NULL;
    conf.logBufferCallback = NULL;
    conf.logData = NULL;

    TSS2_RC tctiError;
    tctiError = InitSocketTcti(tctiContext, &tctiContextSize, &conf, 0);
    if (tctiError) {
        fprintf(stderr, "Error: InitSocketTcti() returns 0x%X\n", (int) tctiError);
        // TODO: throw/raise an expection to the up level
    }

    TSS2_ABI_VERSION abiVersion;
    abiVersion.tssCreator = TSSWG_INTEROP;
    abiVersion.tssFamily = TSS_SAPI_FIRST_FAMILY;
    abiVersion.tssLevel = TSS_SAPI_FIRST_LEVEL;
    abiVersion.tssVersion = TSS_SAPI_FIRST_VERSION;

    TSS2_RC sapiError;
    sapiError = Tss2_Sys_Initialize(
            sysContext,
            sysContextSize,
            tctiContext,
            &abiVersion);
    if (sapiError) {
        fprintf(stderr, "Error: Tss2_Sys_Initialize() returns 0x%X\n", (int) sapiError);
        // TODO: throw/raise an expection to the up level
    }
}

// 构造函数 DeviceBasedClientContextInitializer()
DeviceBasedClientContextInitializer::DeviceBasedClientContextInitializer(const char *device)
{
    if (!device)
    {
        device = "/dev/tpm0";
    }
    m_device = device;
}

// 析构函数 ~DeviceBasedClientContextInitializer()
DeviceBasedClientContextInitializer::~DeviceBasedClientContextInitializer()
{
}

// 回调函数 initializerCallbackFunc()
void DeviceBasedClientContextInitializer::initializerCallbackFunc(TSS2_TCTI_CONTEXT *tctiContext, size_t tctiContextSize, TSS2_SYS_CONTEXT *sysContext, size_t sysContextSize)
{
    TCTI_DEVICE_CONF conf;
    conf.device_path = (const char *) m_device;
    conf.logCallback = NULL;
    conf.logData = NULL;

    TSS2_RC tctiError;
    tctiError = InitDeviceTcti(tctiContext, &tctiContextSize, &conf);
    if (tctiError) {
        fprintf(stderr, "Error: InitSocketTcti() returns 0x%X\n", (int) tctiError);
        // TODO: throw/raise an expection to the up level
    }

    TSS2_ABI_VERSION abiVersion;
    abiVersion.tssCreator = TSSWG_INTEROP;
    abiVersion.tssFamily = TSS_SAPI_FIRST_FAMILY;
    abiVersion.tssLevel = TSS_SAPI_FIRST_LEVEL;
    abiVersion.tssVersion = TSS_SAPI_FIRST_VERSION;

    TSS2_RC sapiError;
    sapiError = Tss2_Sys_Initialize(
            sysContext,
            sysContextSize,
            tctiContext,
            &abiVersion);
    if (sapiError) {
        fprintf(stderr, "Error: Tss2_Sys_Initialize() returns 0x%X\n", (int) sapiError);
        // TODO: throw/raise an expection to the up level
    }
}

/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <cstdio>
#include <cstdlib>
using namespace std;

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include "TPMCommand.h"

/* 排版格式: 以下函数均使用4个空格缩进，不使用Tab缩进 */

static void PrintHelp()
{
    printf("用法:\n");
    printf("-rmhost 手动指定运行资源管理器(即 resourcemgr)的主机IP地址或主机名 (默认值: %s)\n",
            DEFAULT_HOSTNAME);
    printf("-rmport 手动指定运行资源管理器的主机端口号 (默认值: %d)\n", DEFAULT_RESMGR_TPM_PORT);
}

/// @class MyAppFramework
/// @details
class MyAppFramework
{
    size_t m_TCTIContextSize;
    size_t m_SystemAPIContextSize;
    TSS2_TCTI_CONTEXT *m_tctiContext; // 推荐使用成员变量 m_tctiContext (避免在主程序中使用全局变量 tctiContext).
    TSS2_SYS_CONTEXT *m_sysContext; // 推荐使用成员变量 m_sysContext (避免在主程序中使用全局变量 sysContext).

public:
    /** 构造函数 */
    MyAppFramework();
    /** 析构函数 */
    ~MyAppFramework();
    /** 与本地默认端口上运行的 TSS resource manager 守护进程建立连接 */
    void connectToDefaultLocalResourceManager();
    /** 与任意远程或本地 TSS resource manager 守护进程建立连接 */
    void connectToResourceManager(const char *hostname="127.0.0.1", uint16_t port=2323);
    /** 发送命令帧 */
    void sendCommand(TPMCommand& cmd);
    /**
     * 取回应答帧
     *
     * @note 若该函数执行成功, 返回的数据将被写入之前调用 sendCommand() 时指定的 cmd 对象
     */
    void fetchResponse(
            TPMCommand& cmd, ///< 输出参数, 命令的执行结果会被存入相应的Parameters_Out子结构体
            int32_t timeout=-1 ///< 超时选项. 默认使用负数表示阻塞等待, 直到服务器端相应或者发生严重错误
            );
    /**
     * 切断与守护进程之间的通讯连接
     *
     * @details
     * 优雅地切断之前建立的任意 socket 连接(通常是与 TSS resource manager 守护进程之间的链接)
     * 底层调用 shutdown() 通知对方正常结束会话连接(connection), 然后调用 closesocket() 关闭本地套接字.
     *
     * @todo `#include "MyAppExceptions.hpp"` 分类处理运行时可能抛出的 C++ 异常类型
     * @throws MyAppExceptions::UnableToShutdownConnetion
     * @throws MyAppExceptions::UnableToCloseSocket
     * @throws std::exception
     */
    void disconnect();
};

#include <exception>
int main(int argc, char *argv[])
{
    MyAppFramework framework;
    int count;
    char *hostname = DEFAULT_HOSTNAME;
    uint16_t port = DEFAULT_RESMGR_TPM_PORT;

    count = 1;
    while (count < argc)
    {
        if (0 == strcmp(argv[count], "-rmhost"))
        {
            if (count + 1 >= argc)
            {
                PrintHelp();
                return 1;
            }
            hostname = argv[count + 1];  // 暂时不检查无效的输入参数
            count += 2;
        }
        else if (0 == strcmp(argv[count], "-rmport"))
        {
            if (count + 1 >= argc)
            {
                PrintHelp();
                return 1;
            }
            port = strtoul(argv[count + 1], NULL, 10); // 暂时不检查无效的输入参数
            count += 2;
        }
        else
        {
            PrintHelp();
            return -1;
        }
        // 以上代码提供了一组简单的命令行参数便于调试:
        // 其中包括 [-rmhost IP地址] 和 [-rmport 端口号]
        // 如果不指定命令行参数, 则会直接连接到本机 IP 地址默认端口上运行的资源管理器
    }

    // 测试开始, 首先建立与 TSS resource manager 连接
    framework.connectToResourceManager(hostname, port);
    // ----------------------------------
    printf("%s\n", "测试 Startup 命令");
    TPMCommands::Startup startup;
    try
    {
        startup.disableRestoreSavedState();
        framework.sendCommand(startup);
        framework.fetchResponse(startup);
    }
    catch(std::exception& e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
    }
    // ----------------------------------
    printf("%s\n", "测试 NV DefineSpace 命令");
    TPMCommands::NV::DefineSpace nvdef;
    TPMI_RH_NV_INDEX idx = NV_INDEX_FIRST + 0x000020;
    UINT16 size = 16;
    nvdef.configNVIndex(idx);
    nvdef.configNVIndexDataSize(size);
    nvdef.configNVIndexAuthPassword("My password", 11);
    nvdef.configCreatorAsOwner();
    framework.sendCommand(nvdef);
    framework.fetchResponse(nvdef);
    // ----------------------------------
    printf("%s\n", "测试 Shutdown 命令");
    TPMCommands::Shutdown shutdown;
    try
    {
        shutdown.enbleRestoreSavedState();
        framework.sendCommand(shutdown);
        framework.fetchResponse(shutdown);
    }
    catch (std::exception& e)
    {
        fprintf(stderr, "Error: %s\n", e.what());
    }
    // 测试结束需要手动切断与 TSS resource manager 之间的连接
    framework.disconnect();
    return (0);
}

#include <cassert>

static size_t GetSocketTctiContextSize();

MyAppFramework::MyAppFramework()
{
    m_TCTIContextSize = GetSocketTctiContextSize();
    m_tctiContext = (TSS2_TCTI_CONTEXT *) malloc(m_TCTIContextSize);
    assert(m_tctiContext);
    if (!m_tctiContext)
    {
        exit (EXIT_FAILURE);
    }
    memset(m_tctiContext, 0x00, m_TCTIContextSize);

    m_SystemAPIContextSize = Tss2_Sys_GetContextSize(0);
    m_sysContext = (TSS2_SYS_CONTEXT *) malloc(m_SystemAPIContextSize);
    if (!m_sysContext)
    {
        exit (EXIT_FAILURE);
    }
    memset(m_sysContext, 0x00, m_SystemAPIContextSize);
}

MyAppFramework::~MyAppFramework()
{
    /* 销毁 TCTI 上下文对象 */
    assert(m_tctiContext);
    free(m_tctiContext);

    /* 销毁 System API 上下文对象 */
    assert(m_sysContext);
    free(m_sysContext);
}

void MyAppFramework::connectToResourceManager(const char *hostname, uint16_t port)
{
    TCTI_SOCKET_CONF conf;
    conf.hostname = (char *) hostname;
    conf.port = port;
    conf.logCallback = NULL;
    conf.logBufferCallback = NULL;
    conf.logData = NULL;

    TSS2_RC err;
    err = InitSocketTcti(m_tctiContext, &m_TCTIContextSize, &conf, 0);
    if (err)
    {
        // TODO: throw/raise an expection to the up level
    }

    TSS2_ABI_VERSION abiVersion;
    abiVersion.tssCreator = TSSWG_INTEROP;
    abiVersion.tssFamily = TSS_SAPI_FIRST_FAMILY;
    abiVersion.tssLevel = TSS_SAPI_FIRST_LEVEL;
    abiVersion.tssVersion = TSS_SAPI_FIRST_VERSION;

    TSS2_RC err2;
    err2 = Tss2_Sys_Initialize(
            m_sysContext,
            m_SystemAPIContextSize,
            m_tctiContext,
            &abiVersion);
    if (err2)
    {
        // TODO: throw/raise an expection to the up level
    }
}

void MyAppFramework::connectToDefaultLocalResourceManager()
{
    connectToResourceManager();
}

void MyAppFramework::sendCommand(TPMCommand& cmd)
{
    cmd.buildCmdPacket(m_sysContext); // 调用相应的 TSS 软件栈 Tss2_Sys_XXXX_Prepare() 函数

    // 异步发送命令帧
    TSS2_RC err = Tss2_Sys_ExecuteAsync(m_sysContext);
    if (err)
    {
        // TODO: throw/raise an expection to the up level
    }
}

void MyAppFramework::fetchResponse(TPMCommand& cmd, int32_t timeout)
{
    if (timeout < 0)
    {
        timeout = TSS2_TCTI_TIMEOUT_BLOCK;
    }
    TSS2_RC err = Tss2_Sys_ExecuteFinish(m_sysContext, timeout);
    if (err)
    {
        // TODO: throw/raise an expection to the up level
    }
    cmd.unpackRspPacket(m_sysContext); // 调用相应的 TSS 软件栈 Tss2_Sys_XXXX_Complete() 函数
}

void MyAppFramework::disconnect()
{
    assert(m_sysContext);
    Tss2_Sys_Finalize(m_sysContext);

    assert(m_tctiContext);
    const TSS2_TCTI_CONTEXT_COMMON_CURRENT *ctx =
            (TSS2_TCTI_CONTEXT_COMMON_CURRENT *) m_tctiContext;
    if (!(ctx->finalize))
    {
        return;
    }
    else if (ctx->version < 1)
    {
        return;
    }
    ctx->finalize(m_tctiContext);
}

size_t GetSocketTctiContextSize()
{
    TCTI_SOCKET_CONF emptyConf;
    size_t size;
    TSS2_RC err;

    err = InitSocketTcti(NULL, &size, &emptyConf, 0);
    if (err)
    {
        fprintf(stderr,
                "Error: Failed to fetch size of TSS2_TCTI_CONTEXT from libtcti-socket\n");
        fprintf(stderr, "(This error should NEVER happen)\n");
        exit(0);
    }
    return size;
}

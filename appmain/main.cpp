/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <cstdio>
#include <cstdlib>
using namespace std;

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#ifndef DEFAULT_RESMGR_TPM_PORT /* @note This mircro and the legacy resourcemgr has been removed by upstream developer since 2017-05-09. @see https://github.com/01org/TPM2.0-TSS/commit/7966ef8916f79ed09eab966a58d773f413fbb67f#diff-9b5d40e51314bbf4fdfc0997a4b58838L41 */
    #warning // DEFAULT_RESMGR_TPM_PORT was removed from <tcti_socket.h>!
    #warning // You should either use tcti_tabrmd.h or tcti-tabrmd.h (which is a replacement to the legacy resourcemgr), or directly connect to port 2321 of the simulator without a resourcemgr!
    #warning // See https://github.com/01org/tpm2-abrmd
    #include <stdint.h>
    const uint16_t DEFAULT_RESMGR_TPM_PORT=DEFAULT_SIMULATOR_TPM_PORT;
#endif
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

static void WriteMyRSAKeyParameters(TPMT_PUBLIC& publicArea, TPMI_RSA_KEY_BITS keyBits=2048);

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

    // ---------------------------------------
    printf("\n");
    printf("测试 CreatePrimary 命令\n");
    TPMCommands::CreatePrimary createprimary;
    const char *primaryPassword = "abcd";
    const UINT16 primaryPasswordLen = strlen(primaryPassword);
    TPMT_PUBLIC publicArea;
    WriteMyRSAKeyParameters(publicArea, 2048); // 使用子函数内预先的设置密钥算法类型
    const TPMI_RH_HIERARCHY hierarchy = TPM_RH_NULL;
    if (TPM_RH_NULL == hierarchy)
    {
        printf("We will create a new key in TPM NULL-hierarchy.\n");
    }

    createprimary.configAuthHierarchy(hierarchy);
    createprimary.configAuthSession(TPM_RS_PW);
    createprimary.configAuthPassword("", 0);
    createprimary.configKeyNameAlg(TPM_ALG_SHA1);
    createprimary.configKeySensitiveData(primaryPassword, primaryPasswordLen, "", 0); // 设置密钥节点密码和附加敏感数据
    createprimary.configPublicData(publicArea);
    try
    {
        framework.sendCommand(createprimary);
        framework.fetchResponse(createprimary);

        // 分析 CreatePrimary 命令创建的句柄
        printf("New primary key created successfully! Handle=0x%8.8x\n", createprimary.outObjectHandle());

        // 分析 CreatePrimary 命令创建的密钥节点名
        const TPM2B_NAME& keyName = createprimary.outName();
        printf("keyName.t.size=%d\n", keyName.t.size);
        printf("keyName data: ");
        for (size_t i=0; i<keyName.t.size; i++)
        {
            printf("0x%02X,", keyName.t.name[i]);
        }
        printf("\n");
    }
    catch (...)
    {
        fprintf(stderr, "Unknown Error\n");
    }

    // ------------------------------------------------------------------------
    printf("\n");
    printf("测试 Create 命令(以 HMACKeyCreate 为例)\n");
    TPMCommands::HMACKeyCreate create;
    const char *ChildPassword = "child password";
    const UINT16 ChildPasswordLen = strlen("child password");
    printf("We will create a child key node under parent(0x%08X).\n",
            createprimary.outObjectHandle());
    create.configAuthParent(createprimary.outObjectHandle());
    create.configAuthSession(TPM_RS_PW);
    create.configAuthPassword(primaryPassword, primaryPasswordLen);
    create.configKeySensitiveData(ChildPassword, ChildPasswordLen, "", 0);
    create.configKeyNameAlg(TPM_ALG_SHA1);
    create.configHMACKeyParameters(TPM_ALG_SHA1);
    try
    {
        framework.sendCommand(create);
        framework.fetchResponse(create);
        printf("Child key node has been created successfully.\n");
    }
    catch (...)
    {
        fprintf(stderr, "Unknown Error\n");
    }

    // ------------------------------------------------------------------------
    printf("\n");
    printf("测试 Load 命令\n");
    TPMCommands::Load load;
    load.configAuthParent(createprimary.outObjectHandle());
    load.configAuthSession(TPM_RS_PW);
    load.configAuthPassword(primaryPassword, primaryPasswordLen);
    load.configPrivateData(create.outPrivate());
    load.configPublicData(create.outPublic());
    try
    {
        framework.sendCommand(load);
        framework.fetchResponse(load);
        const TPM2B_NAME& keyName = load.outName();
        printf("Load 命令取回的结果是: keyName.t.size=%d\n", keyName.t.size);
        printf("keyName data: ");
        for (size_t i=0; i<keyName.t.size; i++)
        {
            printf(" 0x%02X,", keyName.t.name[i]);
        }
        printf("\n");
        printf("Child key node has been loaded successfully. Child handle=0x%08X\n", load.outObjectHandle());
    }
    catch (...)
    {
        fprintf(stderr, "Unknown Error\n");
    }
    // ------------------------------------
    printf("\n");
    printf("测试 ReadPublic 命令\n");
    TPMCommands::ReadPublic readpub;
    readpub.configObject(load.outObjectHandle());
    try
    {
        framework.sendCommand(readpub);
        framework.fetchResponse(readpub);
        const TPM2B_NAME& keyName = readpub.outName();
        printf("ReadPublic 命令取回的结果是: keyName.t.size=%d\n", keyName.t.size);
        printf("keyName data: ");
        for (size_t i=0; i<keyName.t.size; i++)
        {
            printf(" 0x%02X,", keyName.t.name[i]);
        }
        printf("\n");
    }
    catch (...)
    {
        fprintf(stderr, "Unknown Error\n");
    }

    // 测试结束需要手动切断与 TSS resource manager 之间的连接
    framework.disconnect();
    return (0);
}

static void WriteMyRSAKeyParameters(TPMT_PUBLIC& publicArea, TPMI_RSA_KEY_BITS keyBits)
{
    publicArea.type = TPM_ALG_RSA;
    publicArea.nameAlg = TPM_ALG_SHA1;
    publicArea.objectAttributes.val = 0;
    publicArea.objectAttributes.fixedTPM = 1;
    publicArea.objectAttributes.fixedParent = 1;
    publicArea.objectAttributes.restricted = 1;
    publicArea.objectAttributes.userWithAuth = 1;
    publicArea.objectAttributes.sensitiveDataOrigin = 1;
    publicArea.objectAttributes.decrypt = 1;
    publicArea.objectAttributes.sign = 0;
    publicArea.authPolicy.t.size = 0;
    publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
    publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    publicArea.parameters.rsaDetail.keyBits = keyBits;
    publicArea.parameters.rsaDetail.exponent = 0;
    publicArea.unique.rsa.t.size = 0;
    if (TPM_ALG_RSA == publicArea.type)
    {
        printf("Key type: RSA.\n");
        printf("Key size: %d bits.\n", publicArea.parameters.rsaDetail.keyBits);
    }
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
        fprintf(stderr, "Tss2_Sys_ExecuteFinish() returns err = 0x%X\n", err);
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

/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <stdexcept>
using std::exception;
#include <cassert>
#include <cstdio>
#include <cstdlib>
using namespace std;

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include "TPMCommand.h"
#include "TestCase.h"

/* 排版格式: 以下函数均使用4个空格缩进，不使用Tab缩进 */

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
    /** 与任意远程或本地模拟器守护进程建立连接 */
    void connectToSimulatorServer(const char *hostname="127.0.0.1", uint16_t port=2321);
    /** 发送命令帧 */
    void sendCommand(TPMCommand& cmd);
    /**
     * 取回应答帧
     *
     * @note 若该函数执行成功, 返回的数据将被写入之前调用 sendCommand() 时指定的 cmd 对象
     */
    void fetchResponse(
            TPMCommand& cmd, ///< 输出参数, 命令的执行结果会被存入相应的Parameters_Out子结构体
            int32_t timeout=-1 ///< 超时选项. 默认使用负数表示阻塞等待, 直到服务器端应答或者发生其他严重错误
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

static size_t GetSocketTctiContextSize()
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
        return 0;
    }
    return size;
}

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

void MyAppFramework::connectToSimulatorServer(const char *hostname, uint16_t port)
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
        throw err;
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

void TestCase::HashingShortMessageWithin1024Bytes(const char *hostname, unsigned int port)
{
    // 测试开始, 首先建立与 TSS resource manager 连接
    MyAppFramework framework;
    framework.connectToSimulatorServer(hostname, (uint16_t) (port & 0xFFFF));
    ///////////////////////////////////////////////////////////////////////////
    TPMCommands::Hash hash;
    const char *szMessage = "abc";
    printf("测试用例-1 szMessage: \"%s\", (共%d字节)\n", szMessage, (int)strlen(szMessage));
    printf("预期的 SHA256 哈希摘要={ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad}\n");
    printf("预期的 SHA1 哈希摘要={a9:99:3e:36:47:06:81:6a:ba:3e:25:71:78:50:c2:6c:9c:d0:d8:9d}\n");
    try
    {
        printf("配置第一条命令帧(计算SHA256)\n");
        hash.configHashAlgorithmUsingSHA256();
        hash.configInputData(szMessage, strlen(szMessage));

        printf("发送命令帧\n");
        framework.sendCommand(hash);
        framework.fetchResponse(hash);

        printf("取回的 SHA256 摘要结果如下:\n");
        {
            const TPM2B_DIGEST& digest = hash.outHash();
            printf("digest.t.size=%d\n", digest.t.size);
            printf("digest.t.data={");
            if (digest.t.size >= 1)
            {
                int size = digest.t.size;
                int last = size-1;
                for (int i=0; i<=size-2; i++)
                {
                    printf("%02x:", digest.t.buffer[i]);
                }
                printf("%02x", digest.t.buffer[last]);
            }
            printf("}\n");
        }

        printf("配置第二条命令帧(计算SHA1)\n");
        hash.configHashAlgorithmUsingSHA1();
        hash.configInputData(szMessage, strlen(szMessage));

        printf("发送命令桢\n");
        framework.sendCommand(hash);
        framework.fetchResponse(hash);

        printf("取回的 SHA1 摘要结果如下:\n");
        {
            const TPM2B_DIGEST& digest = hash.outHash();
            printf("digest.t.size=%d\n", digest.t.size);
            printf("digest.t.data={");
            if (digest.t.size >= 1)
            {
                int size = digest.t.size;
                int last = size-1;
                for (int i=0; i<=size-2; i++)
                {
                    printf("%02x:", digest.t.buffer[i]);
                }
                printf("%02x", digest.t.buffer[last]);
            }
            printf("}\n");
        }
    }
    catch (...)
    {
        fprintf(stderr, "Unknown Error\n");
    }
    ///////////////////////////////////////////////////////////////////////////
    // 测试结束需要手动切断与 TSS resource manager 之间的连接
    framework.disconnect();
}

void TestCase::HashingLongMessageMoreThan1024Bytes(const char *hostname, unsigned int port)
{
    // 测试开始, 首先建立与 TSS resource manager 连接
    MyAppFramework framework;
    framework.connectToSimulatorServer(hostname, (uint16_t) (port & 0xFFFF));
    // 测试结束需要手动切断与 TSS resource manager 之间的连接
    framework.disconnect();
}

static void SigningAndSignatureVerification_SubTest1(MyAppFramework& framework)
{
    printf("步骤一: 手动执行一条 Hash 命令, 输出一个哈希摘要值\n");
    const char szMessage[] = "abc";
    printf("SHA256 测试用例-1 szMessage[]: \"%s\", (共%d字节)\n", szMessage, (int)strlen(szMessage));
    printf("预期的 SHA256 哈希摘要={ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad}\n");
    TPMCommands::Hash hash;
    try
    {
        hash.configHashAlgorithmUsingSHA256();
        hash.configInputData(szMessage, strlen(szMessage));

        printf("发送 Hash 命令\n");
        framework.sendCommand(hash);
        framework.fetchResponse(hash);

        printf("取回 SHA256 摘要结果如下:\n");
        const TPM2B_DIGEST& digest = hash.outHash();
        printf("digest.t.size=%d\n", digest.t.size);
        printf("digest.t.data={");
        if (digest.t.size >= 1)
        {
            int size = digest.t.size;
            int last = size-1;
            for (int i=0; i<=size-2; i++)
            {
                printf("%02x:", digest.t.buffer[i]);
            }
            printf("%02x", digest.t.buffer[last]);
        }
        printf("}\n");
    }
    catch (...)
    {
        fprintf(stderr, "Unknown Error\n");
    }
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    printf("步骤二: 调用 CreatePrimary 命令, 生成一个主节点(Primary 节点)\n");
    TPMCommands::CreatePrimary createprimary;
    const char *primaryPassword = "abcd";
    const UINT16 primaryPasswordLen = strlen(primaryPassword);
    try
    {
        TPMT_PUBLIC publicArea;

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
        publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
        publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        publicArea.parameters.rsaDetail.keyBits = 2048;
        publicArea.parameters.rsaDetail.exponent = 0;
        publicArea.unique.rsa.t.size = 0;
        if (TPM_ALG_RSA == publicArea.type)
        {
            printf("Key type: RSA.\n");
            printf("Key size: %d bits.\n", publicArea.parameters.rsaDetail.keyBits);
        }
        createprimary.configPublicData(publicArea);

        const TPMI_RH_HIERARCHY hierarchy = TPM_RH_OWNER;
        if (TPM_RH_NULL == hierarchy)
        {
            printf("We will create a new key in TPM NULL-hierarchy.\n");
        }
        else if (TPM_RH_OWNER == hierarchy)
        {
            printf("We will create a new key in TPM Storage-hierarchy(TPM_RH_OWNER).\n");
        }
        createprimary.configAuthHierarchy(hierarchy);
        createprimary.configAuthSession(TPM_RS_PW);
        createprimary.configAuthPassword("", 0);
        createprimary.configKeyNameAlg(TPM_ALG_SHA1); // 备注: 前面已经设置过一次 "publicArea.nameAlg = TPM_ALG_SHA1;" 重复设置应该没有问题
        createprimary.configKeySensitiveData(primaryPassword, primaryPasswordLen, "", 0);

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
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    printf("步骤三: 组合调用 Create 和 Load 命令, 在主节点下加载密钥子节点\n");
    TPMCommands::Create create;
    TPMCommands::Load load;
    const char *ChildPassword = "child password";
    const UINT16 ChildPasswordLen = strlen("child password");
    try
    {
        printf("We will create a child key node under parent(0x%08X).\n",
                createprimary.outObjectHandle());
        create.configAuthParent(createprimary.outObjectHandle());
        create.configAuthSession(TPM_RS_PW);
        create.configAuthPassword(primaryPassword, primaryPasswordLen);
        create.configKeySensitiveData(ChildPassword, ChildPasswordLen, "", 0);
        TPM2B_PUBLIC inPublic;
        {
            inPublic.t.publicArea.type = TPM_ALG_RSA;
            inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;
            inPublic.t.publicArea.objectAttributes.val = 0;
            inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
            inPublic.t.publicArea.objectAttributes.fixedParent = 1;
            inPublic.t.publicArea.objectAttributes.restricted = 0; // 必须清除 restricted 标志位. 原因未知, 需要进一步研究
            inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
            inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
            inPublic.t.publicArea.objectAttributes.decrypt = 1; // 暂时不确定 decrypt 是否影响签名或签名校验
            inPublic.t.publicArea.objectAttributes.sign = 1; // 单独设置属性签名密钥
            inPublic.t.publicArea.authPolicy.t.size = 0;
//          inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
            inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL; // algorithm 不能被设置为 TPM_ALG_AES, 原因未知, 需要进一步研究
            inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
            inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
            inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
            inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
            inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
            inPublic.t.publicArea.unique.rsa.t.size = 0;
            if (TPM_ALG_RSA == inPublic.t.publicArea.type)
            {
                printf("Key type: RSA.\n");
                printf("Key size: %d bits.\n", inPublic.t.publicArea.parameters.rsaDetail.keyBits);
            }
        }
        create.configPublicData(inPublic);

        framework.sendCommand(create);
        framework.fetchResponse(create);
        printf("Child key node has been created successfully.\n");

        load.configAuthParent(createprimary.outObjectHandle());
        load.configAuthSession(TPM_RS_PW);
        load.configAuthPassword(primaryPassword, primaryPasswordLen);
        load.configPrivateData(create.outPrivate());
        load.configPublicData(create.outPublic());

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
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    printf("步骤四: 测试 Sign 命令\n");
    printf("这里将重复2轮测试检查使用 RSASSA-PKCS#1_v1.5 签名方案时的签名输出值.\n");
    printf("预期2轮输出应该完全相同\n");
    printf("(该方案主要用于向前兼容部分历史遗留的旧系统, 特点是对同一输入进行若干次 RSA 签名每次输出都将完全相同). 方案代码TPM_ALG_RSASSA=0x0014\n");
    printf("步骤 4.1: 实验组\n");
    TPMCommands::Sign sign;
    try
    {
        const TPM2B_DIGEST& digest = hash.outHash();
        const TPMT_TK_HASHCHECK& ticket = hash.outValidationTicket();

        printf("digest.t.size=%d\n", digest.t.size);
        sign.configDigestToBeSigned(digest.t.buffer, digest.t.size);
        sign.configScheme(DigitalSignatureSchemes::RSASSA_PKCS1_V1_5_SHA256);
        sign.configValidationTicket(ticket);
        sign.configSigningKey(load.outObjectHandle());
        sign.configAuthPassword(ChildPassword, ChildPasswordLen);
        sign.configAuthSession(TPM_RS_PW);

        framework.sendCommand(sign);
        framework.fetchResponse(sign);

        // 分析 Sign 命令输出的数字签名
        const TPMT_SIGNATURE& signature = sign.outSignature();
        printf("sigAlg=0x%04X (备注: TPM_ALG_RSASSA=0x%04X)\n", signature.sigAlg, TPM_ALG_RSASSA);
        printf("hashAlg=0x%04X (备注: TPM_ALG_SHA1=0x%04X,  TPM_ALG_SHA256=0x%04X)\n", signature.signature.any.hashAlg, TPM_ALG_SHA1, TPM_ALG_SHA256);
        if (signature.sigAlg == TPM_ALG_RSASSA)
        {
            const BYTE *buffer = signature.signature.rsassa.sig.b.buffer;
            const UINT16 size =  signature.signature.rsassa.sig.b.size;
            printf("数字签名 size=%d\n", size);
            printf("---- BEGIN ----\n");
            for (UINT16 i = 0; i < size; i++)
            {
                printf("%02X", buffer[i]);
                if ((i & 0x1F) == 0x1F)
                {
                    printf("\n");
                }
            }
            printf("----- END -----\n");
        }

        printf("\n");
        printf("步骤 4.2: 对照组\n");
        printf("重复进行数字签名, 作为对照组. 检查 RSASSA_PKCS#1 v1.5 方案对同一输入签名两次, 输出的两个数字签名值是否相同\n");
        printf("预期结果: 两次输出的数字签名值应该完全相同\n");
        TPMCommands::Sign sign2;
        {
            sign2.configDigestToBeSigned(digest.t.buffer, digest.t.size);
            sign2.configValidationTicket(ticket);
            sign2.configScheme(DigitalSignatureSchemes::RSASSA_PKCS1_V1_5_SHA256);
            sign2.configSigningKey(load.outObjectHandle());
            sign2.configAuthPassword(ChildPassword, ChildPasswordLen);
            sign2.configAuthSession(TPM_RS_PW);

            framework.sendCommand(sign2);
            framework.fetchResponse(sign2);

            // 打印第二条命令输出的数字签名
            const TPMT_SIGNATURE& out2 = sign2.outSignature();
            printf("sigAlg=0x%04X (备注: TPM_ALG_RSASSA=0x%04X)\n", out2.sigAlg, TPM_ALG_RSASSA);
            printf("hashAlg=0x%04X (备注: TPM_ALG_SHA1=0x%04X,  TPM_ALG_SHA256=0x%04X)\n", out2.signature.any.hashAlg, TPM_ALG_SHA1, TPM_ALG_SHA256);
            if (out2.sigAlg == TPM_ALG_RSASSA)
            {
                const BYTE *buffer = out2.signature.rsassa.sig.b.buffer;
                const UINT16 size =  out2.signature.rsassa.sig.b.size;
                printf("数字签名 size=%d\n", size);
                printf("---- BEGIN ----\n");
                for (UINT16 i = 0; i < size; i++)
                {
                    printf("%02X", buffer[i]);
                    if ((i & 0x1F) == 0x1F)
                    {
                        printf("\n");
                    }
                }
                printf("----- END -----\n");
            }
        }
    }
    catch (...)
    {
        fprintf(stderr, "Unknown Error\n");
    }
    printf("\n");
    /////////////////////////////////////////////////////////////////////////////
    printf("步骤五: 这里只对之前生成的数字签名进行一次自我校验\n");
    TPMCommands::VerifySignature verifysignature;
    try
    {
        const TPM2B_DIGEST& digest = hash.outHash();
        const TPMT_SIGNATURE& signature = sign.outSignature();
        TPM_HANDLE keyHandle = load.outObjectHandle();

        verifysignature.configSigningKey(keyHandle);
        verifysignature.configDigestWithSignature(digest, signature);

        framework.sendCommand(verifysignature);
        framework.fetchResponse(verifysignature);

        printf("数字签名校验的结果: 有效\n");
        printf("本次操作附带生成一条操作凭据 validataion ticket:\n");
        const TPMT_TK_VERIFIED& ticket = verifysignature.outValidationTicket();
        printf("ticket.tag = 0x%X(备注: 期望值 TPM_ST_VERIFIED=0x%X)\n", ticket.tag, TPM_ST_VERIFIED);
    }
    catch (TSS2_RC rc)
    {
        TSS2_RC mask1 = TSS2_ERROR_LEVEL_MASK; // 错误级别掩码
        TSS2_RC mask2 = (0xFF - TPM_RC_P); // TPM 级别应答码详细错误码
        if ((TSS2_TPM_ERROR_LEVEL == (rc & mask1)) && (TPM_RC_SIGNATURE == (rc & mask2)))
        {
            printf("发现数字签名不匹配, TPM_RC_SIGNATURE(0x%X), rc=0x%X\n", TPM_RC_SIGNATURE, rc);
            printf("TPM_RC_SIGNATURE(0x%X)\n", TPM_RC_SIGNATURE);
        }
        else
        {
            fprintf(stderr, "TPM has returned a unknown error response code 0x%X\n", rc);
            fprintf(stderr, "Please try to run \"tpm2_rc_decode 0x%X\" to see more details.\n", rc);
        }
    }
    catch (...)
    {
        fprintf(stderr, "An unknown error happened in TPM command VerifySignature\n");
    }
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    printf("最后一步: 清理测试现场, 调用 Flush 命令清除密钥节点\n");
    TPMCommands::FlushLoadedKeyNode flush1;
    TPMCommands::FlushLoadedKeyNode flush2;
    try
    {
        flush1.configKeyNodeToFlushAway(createprimary.outObjectHandle());

        printf("发送命令, 让 TPM 删除 CreatePrimary 命令创建的主节点\n");
        framework.sendCommand(flush1);
        framework.fetchResponse(flush1);
        printf("flush1 成功删除了主节点\n");
    }
    catch (std::exception& e)
    {
        fprintf(stderr, "flush1: An error happened: %s\n", e.what());
    }
    catch (...)
    {
        fprintf(stderr, "Unknown error happened in TPM command FlushLoadedKeyNode\n");
    }
    try
    {
        flush2.configKeyNodeToFlushAway(load.outObjectHandle());

        printf("发送命令, 让 TPM 删除 Create/Load 命令输出的子节点\n");
        framework.sendCommand(flush2);
        framework.fetchResponse(flush2);
        printf("flush2 成功删除了子节点\n");
    }
    catch (std::exception& e)
    {
        fprintf(stderr, "flush2: An error happened: %s\n", e.what());
    }
    catch (...)
    {
        fprintf(stderr, "Unknown error happened in TPM command FlushLoadedKeyNode\n");
    }
    printf("\n");
}

static void SigningAndSignatureVerification_SubTest2(MyAppFramework& framework);

void TestCase::SigningAndSignatureVerification(const char *hostname, unsigned int port)
{
    // 说明:
    //
    // 按顺序依次执行若干个自测试,
    // 为其中每一个子测试独立建立一个链接, 访问 TSS resource manager
    // 每个子测试结束时手动切断这个链接. (下一个自测试开始时另外创建一个新链接)
    MyAppFramework framework1;
    framework1.connectToSimulatorServer(hostname, (uint16_t) (port & 0xFFFF));
    printf("\n【自测试-1】\n");
    SigningAndSignatureVerification_SubTest1(framework1);
    framework1.disconnect();

    MyAppFramework framework2;
    framework2.connectToSimulatorServer(hostname, (uint16_t) (port & 0xFFFF));
    printf("\n【自测试-2】\n");
    SigningAndSignatureVerification_SubTest2(framework2);
    framework2.disconnect();
}

void TestCase::HMAC::RFC2202TestCasesForHMACSHA1(const char *hostname, unsigned int port)
{
    // 测试开始, 首先建立与 TSS resource manager 连接
    MyAppFramework framework;
    framework.connectToSimulatorServer(hostname, (uint16_t) (port & 0xFFFF));
    ///////////////////////////////////////////////////////////////////////////
    printf("测试 HMAC(基于哈希摘要的消息鉴别码), 其中用到 LoadExternal 和 HMAC 两条命令\n");
    const char *data = "Hi There"; // HMAC-SHA-1 测试数据, 来自 https://tools.ietf.org/html/rfc2202#section-3
    printf("原始明文消息为: data[] = \"%s\"\n", data);
    const UINT8 KeyBuffer[20] = // 20 字节 HMAC 签名密钥值
    {   /** HMAC-SHA-1 测试用例来自 https://tools.ietf.org/html/rfc2202#section-3 */
        0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b,
    };
    const UINT16 KeySize = sizeof(KeyBuffer); // 单位: 字节
    printf("密钥长度: KeySize=%d 字节\n", KeySize);
    printf("密钥内容为: KeyBuffer[]={\n");
    printf("    ");
    for (UINT16 i=0; i<KeySize; i++)
    {
        printf("%02x:", KeyBuffer[i]);
    }
    printf("\n");
    printf("}\n");
    printf("预期输出: HMAC={\n");
    printf("    b6:17:31:86:55:05:72:64:e2:8b:c0:b6:fb:37:8c:8e:f1:46:be:00\n");
    printf("}\n");
    printf("(这组 HMAC-SHA-1 测试数据, 选自 RFC2202 , 网址为: https://tools.ietf.org/html/rfc2202#section-3 )\n");

    TPMCommands::LoadExternal loadextn;
    TPMCommands::HMAC hmac; // 单条 HMAC 命令, 可以处理不超过 1024 字节数据
    try
    {
        printf("设置第一条命令帧参数\n");
        loadextn.configHierarchy(TPM_RH_NULL);
        loadextn.configSensitiveDataBits(KeyBuffer, KeySize); // 签名密钥值
        loadextn.configHMACKeyUsingHashAlgorithm();
        const char *ExternalKeyPassword = "";
        const UINT16 ExternalKeyPasswordLen = strlen(ExternalKeyPassword);
        loadextn.configKeyAuthValue(ExternalKeyPassword, ExternalKeyPasswordLen);
        printf("发送 LoadExternal 命令桢, 加载外部密钥节点\n");
        framework.sendCommand(loadextn);
        framework.fetchResponse(loadextn);
        const TPM_HANDLE h = loadextn.outObjectHandle();
        const TPM2B_NAME& keyName = loadextn.outName();
        printf("成功加载外部密钥, 返回的密钥句柄为 h=0x%08X\n", h);
        printf("LoadExternal 命令返回的节点: keyName.t.size=%d\n", keyName.t.size);
        printf("keyName data: ");
        for (size_t i=0; i<keyName.t.size; i++)
        {
            printf(" 0x%02X,", keyName.t.name[i]);
        }
        printf("\n");

        printf("设置第二条命令帧参数\n");
        TPM_HANDLE keyHandle = loadextn.outObjectHandle();
        hmac.configHMACKey(keyHandle);
        hmac.configAuthSession(TPM_RS_PW);
        hmac.configAuthPassword(ExternalKeyPassword, ExternalKeyPasswordLen);
        hmac.configInputData(data, strlen(data));
        hmac.configUsingHashAlgorithmSHA1();

        printf("发送 HMAC 命令桢\n");
        framework.sendCommand(hmac);
        framework.fetchResponse(hmac);

        const TPM2B_DIGEST& result = hmac.outHMAC();
        printf("指定的密钥句柄为 keyHandle=0x%08X\n", keyHandle);
        printf("输入明文消息为: \"%s\"\n", data);
        printf("HMAC 输出结果如下, result.t.data[]={\n");
        printf("    ");
        for (UINT16 i=0; i<result.t.size; i++)
        {
            printf("%02x:", result.t.buffer[i]);
        }
        printf("\n");
        printf("}\n");
    }
    catch (TSS2_RC rc)
    {
        fprintf(stderr, "loadextn or hmac has returned a TSS2 error code 0x%X\n", rc);
        fprintf(stderr, "Please try to run \"tpm2_rc_decode 0x%X\" to see more details.\n", rc);
    }
    catch (...)
    {
        fprintf(stderr, "An unknown error happened in TPM command LoadExternal or HMAC\n");
    }
    // ------------------------------------
    TPM_HANDLE ht = (loadextn.outObjectHandle() & 0xFF000000);
    if (ht == 0x80000000 || ht == 0x810000000)
    {
        printf("调用 Flush 命令清理测试现场:\n");
        try
        {
            TPMCommands::FlushLoadedKeyNode flush;
            flush.configKeyNodeToFlushAway(loadextn.outObjectHandle());
            printf("发送 FlushContext 命令桢, 让 TPM 删除之前 LoadExternal 命令加载的节点\n");
            framework.sendCommand(flush);
            framework.fetchResponse(flush);
            printf("删除完毕\n");
        }
        catch (std::exception& e)
        {
            fprintf(stderr, "flush: An error happened: %s\n", e.what());
        }
        catch (...)
        {
            fprintf(stderr, "Unknown error happened in TPM command FlushLoadedKeyNode\n");
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // 测试结束需要手动切断与 TSS resource manager 之间的连接
    framework.disconnect();
}

void TestCase::HMAC::MyTestCaseForHMACSHA1UsingTPMProtectedHMACKey(const char *hostname, unsigned int port)
{
    printf("函数名: %s()\n", __FUNCTION__);
    printf("本函数将演示如何在 TPM 的保护区中创建一个对称密钥并使用该密钥进行 HMAC 运算输出 HMAC 结果(即: 基于哈希摘要的消息鉴别码)\n");
    MyAppFramework framework;
    // 测试开始, 首先建立与 TSS resource manager 连接
    framework.connectToSimulatorServer(hostname, port);
    ///////////////////////////////////////////////////////////////////////////
    printf("步骤一(准备步骤): 调用 CreatePrimary 命令创建一个存储密钥\n");
    const char *primaryPassword = "abcd";
    const UINT16 primaryPasswordLen = strlen(primaryPassword);
    TPMCommands::CreatePrimary createprimary;
    try
    {
        TPMT_PUBLIC publicArea;

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
        publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
        publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        publicArea.parameters.rsaDetail.keyBits = 2048;
        publicArea.parameters.rsaDetail.exponent = 0;
        publicArea.unique.rsa.t.size = 0;
        if (TPM_ALG_RSA == publicArea.type)
        {
            printf("Key type: RSA.\n");
            printf("Key size: %d bits.\n", publicArea.parameters.rsaDetail.keyBits);
        }
        createprimary.configPublicData(publicArea);

        const TPMI_RH_HIERARCHY hierarchy = TPM_RH_OWNER;
        if (TPM_RH_NULL == hierarchy)
        {
            printf("We will create a new key in TPM NULL-hierarchy.\n");
        }
        else if (TPM_RH_OWNER == hierarchy)
        {
            printf("We will create a new key in TPM Storage-hierarchy(TPM_RH_OWNER).\n");
        }
        createprimary.configAuthHierarchy(hierarchy);
        createprimary.configAuthSession(TPM_RS_PW);
        createprimary.configAuthPassword("", 0);
        createprimary.configKeyNameAlg(TPM_ALG_SHA1); // 备注: 前面已经设置过一次 "publicArea.nameAlg = TPM_ALG_SHA1;" 重复设置应该没有问题
        createprimary.configKeySensitiveData(primaryPassword, primaryPasswordLen, "", 0); // 设置密钥节点密码和附加敏感数据
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
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    printf("步骤二(准备步骤): 让 TPM 创建并加载一个对称密钥, 以便稍后用于计算 HMAC 值.\n");
    const char *ChildPassword = "child password";
    const UINT16 ChildPasswordLen = strlen("child password");
    TPMCommands::HMACKeyCreate create;
    TPMCommands::Load load;
    try
    {
        printf("设置 Create 命令帧参数.\n");
        create.configAuthParent(createprimary.outObjectHandle());
        create.configAuthSession(TPM_RS_PW);
        create.configAuthPassword(primaryPassword, primaryPasswordLen);
        create.configKeySensitiveData(ChildPassword, ChildPasswordLen, "", 0);
        create.configKeyNameAlg(TPM_ALG_SHA1);
        create.configHMACKeyParameters(TPM_ALG_SHA1);

        printf("发送 Create 命令帧.\n");
        framework.sendCommand(create);
        framework.fetchResponse(create);
        printf("Create 命令执行成功.\n");

        printf("设置 Load 命令帧参数\n");
        load.configAuthParent(createprimary.outObjectHandle());
        load.configAuthSession(TPM_RS_PW);
        load.configAuthPassword(primaryPassword, primaryPasswordLen);
        load.configPrivateData(create.outPrivate());
        load.configPublicData(create.outPublic());

        printf("发送 Load 命令帧.\n");
        framework.sendCommand(load);
        framework.fetchResponse(load);
        printf("密钥节点加载成功. Child handle=0x%08X\n", load.outObjectHandle());

        const TPM2B_NAME& keyName = load.outName();
        printf("Load 命令取回的结果是: keyName.t.size=%d\n", keyName.t.size);
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
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    printf("步骤三: 测试 HMAC 命令\n");
    const char data[] = "Hi There"; // HMAC-SHA-1 测试数据, 来自 https://tools.ietf.org/html/rfc2202#section-3
    TPMCommands::HMAC hmac; // 单条 HMAC 命令, 可以处理不超过 1024 字节数据
    try /* 发送 HMAC 命令 */
    {
        TPM_HANDLE childKeyHandle = load.outObjectHandle();
        hmac.configHMACKey(childKeyHandle); // 引用之前成功加载的 HMAC 密钥句柄
        hmac.configAuthSession(TPM_RS_PW);
        hmac.configAuthPassword(ChildPassword, ChildPasswordLen);
        hmac.configInputData(data, strlen(data));
        hmac.configUsingHashAlgorithmSHA1();
        framework.sendCommand(hmac);
        framework.fetchResponse(hmac);

        printf("指定的密钥句柄为 childKeyHandle=0x%08X\n", childKeyHandle);
        printf("输入明文消息为: \"%s\"\n", data);
        printf("HMAC 输出结果如下, result.t.buffer = { /* 十六进制数据 */\n");
        const TPM2B_DIGEST& result = hmac.outHMAC();
        for (UINT16 i=0; i<result.t.size; i++)
        {
            printf(" %02X", result.t.buffer[i]);
        }
        printf("\n");
        printf("}\n");
    }
    catch (TSS2_RC rc)
    {
        fprintf(stderr, "hmac: TSS2 error code 0x%X was returned from libsapi\n", rc);
        fprintf(stderr, "Please try to run \"tpm2_rc_decode 0x%X\" to see more details.\n", rc);
    }
    catch (...)
    {
        fprintf(stderr, "TPMCommands::HMAC throws an unexpected exception!\n");
    }
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    printf("测试结束前调用 Flush 命令清理测试现场\n");
    TPMCommands::FlushLoadedKeyNode flush1;
    try
    {
        flush1.configKeyNodeToFlushAway(createprimary.outObjectHandle());
        printf("发送命令, 让 TPM 删除 CreatePrimary 命令创建的主节点\n");
        framework.sendCommand(flush1);
        framework.fetchResponse(flush1);
        printf("删除完毕\n");
    }
    catch (std::exception& e)
    {
        fprintf(stderr, "flush1: An error happened: %s\n", e.what());
    }
    catch (...)
    {
        fprintf(stderr, "Unknown error happened in TPM command FlushLoadedKeyNode\n");
    }
    TPMCommands::FlushLoadedKeyNode flush2;
    try
    {
        flush2.configKeyNodeToFlushAway(load.outObjectHandle());
        printf("发送命令, 让 TPM 删除 Create/Load 命令输出的子节点\n");
        framework.sendCommand(flush2);
        framework.fetchResponse(flush2);
        printf("删除完毕\n");
    }
    catch (std::exception& e)
    {
        fprintf(stderr, "flush2: An error happened: %s\n", e.what());
    }
    catch (...)
    {
        fprintf(stderr, "Unknown error happened in TPM command FlushLoadedKeyNode\n");
    }
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    // 测试结束需要手动切断与 TSS resource manager 之间的连接
    framework.disconnect();
}

void TestCase::MyTestCaseForRSAEncryptionDecryptionUsingTPMProtectedRSAKey(const char *hostname, unsigned int port)
{
    // 测试开始, 首先建立与 TSS resource manager 连接
    MyAppFramework framework;
    framework.connectToSimulatorServer(hostname, (uint16_t) (port & 0xFFFF));
    ///////////////////////////////////////////////////////////////////////////
    printf("步骤1: 调用 CreatePrimary 命令, 生成一个主节点(Primary 节点)\n");
    TPMCommands::CreatePrimary createprimary;
    const char *primaryPassword = "abcd";
    const UINT16 primaryPasswordLen = strlen(primaryPassword);
    try
    {
        TPMT_PUBLIC publicArea;

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
        publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
        publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        publicArea.parameters.rsaDetail.keyBits = 2048;
        publicArea.parameters.rsaDetail.exponent = 0;
        publicArea.unique.rsa.t.size = 0;
        if (TPM_ALG_RSA == publicArea.type)
        {
            printf("Key type: RSA.\n");
            printf("Key size: %d bits.\n", publicArea.parameters.rsaDetail.keyBits);
        }
        createprimary.configPublicData(publicArea);

        const TPMI_RH_HIERARCHY hierarchy = TPM_RH_OWNER;
        if (TPM_RH_NULL == hierarchy)
        {
            printf("We will create a new key in TPM NULL-hierarchy.\n");
        }
        else if (TPM_RH_OWNER == hierarchy)
        {
            printf("We will create a new key in TPM Storage-hierarchy(TPM_RH_OWNER).\n");
        }
        createprimary.configAuthHierarchy(hierarchy);
        createprimary.configAuthSession(TPM_RS_PW);
        createprimary.configAuthPassword("", 0);
        createprimary.configKeyNameAlg(TPM_ALG_SHA1); // 备注: 前面已经设置过一次 "publicArea.nameAlg = TPM_ALG_SHA1;" 重复设置应该没有问题
        createprimary.configKeySensitiveData(primaryPassword, primaryPasswordLen, "", 0);

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
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    printf("步骤2: 组合调用 Create 和 Load 命令, 在主节点下加载密钥子节点\n");
    TPMCommands::Create create;
    TPMCommands::Load load;
    const char *ChildPassword = "child password";
    const UINT16 ChildPasswordLen = strlen("child password");
    try
    {
        printf("We will create a child key node under parent(0x%08X).\n",
                createprimary.outObjectHandle());
        create.configAuthParent(createprimary.outObjectHandle());
        create.configAuthSession(TPM_RS_PW);
        create.configAuthPassword(primaryPassword, primaryPasswordLen);
        create.configKeySensitiveData(ChildPassword, ChildPasswordLen, "", 0);
        TPM2B_PUBLIC inPublic;
        {
            inPublic.t.publicArea.type = TPM_ALG_RSA;
            inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;
            inPublic.t.publicArea.objectAttributes.val = 0;
            inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
            inPublic.t.publicArea.objectAttributes.fixedParent = 1;
            inPublic.t.publicArea.objectAttributes.restricted = 0; // 必须清除 restricted 标志位. 原因未知, 需要进一步研究
            inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
            inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
            inPublic.t.publicArea.objectAttributes.decrypt = 1; // 允许 RSA 私钥用于解密(decrypt)运算
            inPublic.t.publicArea.objectAttributes.sign = 0; // 不允许该 RSA 私钥用于签名(因RSA数字签名和RSA加解密对应的Padding Scheme不同)
            inPublic.t.publicArea.authPolicy.t.size = 0;
            inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
            // 下列两个变量用于设置 RSA 加解密密钥使用 OAEP 方案填充数据块:
            // inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme
            // 和
            // inPublic.t.publicArea.parameters.rsaDetail.scheme.details.oaep.hashAlg
            // 如果改为 rsaDetail.scheme.scheme = TPM_ALG_NULL 则暂不指定数据块填充方案
            inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_OAEP; // 推荐使用 OAEP 填充方案
            inPublic.t.publicArea.parameters.rsaDetail.scheme.details.oaep.hashAlg = TPM_ALG_SHA1; // 其他备选值包括 TPM_ALG_SHA256 等. 注: oaep.hashAlg 不允许设定为 TPM_ALG_NULL
            inPublic.t.publicArea.parameters.rsaDetail.keyBits = 1024; // 密钥位数, 可选取值 1024/2048. 程序运行测试 TPM 模块确认是否支持 4096 位 RSA 密钥, 发现不支持, 应答桢返回错误码0x02C4=(RC_FMT1 | TPM_RC_2 | TPM_RC_P | TPM_RC_VALUE): parameter 2 value is out of range
            inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
            inPublic.t.publicArea.unique.rsa.t.size = 0;
            if (TPM_ALG_RSA == inPublic.t.publicArea.type)
            {
                printf("Key type: RSA.\n");
                printf("Key size: %d bits.\n", inPublic.t.publicArea.parameters.rsaDetail.keyBits);
            }
        }
        create.configPublicData(inPublic);

        framework.sendCommand(create);
        framework.fetchResponse(create);
        printf("Child key node has been created successfully.\n");

        load.configAuthParent(createprimary.outObjectHandle());
        load.configAuthSession(TPM_RS_PW);
        load.configAuthPassword(primaryPassword, primaryPasswordLen);
        load.configPrivateData(create.outPrivate());
        load.configPublicData(create.outPublic());

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
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    printf("步骤3: 测试 Encrypt 和 Decrypt 命令\n");
    TPMCommands::Encrypt encrypt;
    TPMCommands::Decrypt decrypt;
    TPM_HANDLE pubKeyHandle; ///< RSA 公钥
    pubKeyHandle = load.outObjectHandle();
    TPM_HANDLE privkeyHandle; ///< RSA 私钥
    privkeyHandle = load.outObjectHandle();
    const UINT16 RSAKeyBits = create.outPublic().t.publicArea.parameters.rsaDetail.keyBits;
    try
    {
        const char plaintext[] = {'A', 'B', 'C', '\0', 'a', 'b', 'c', '\r', '\n', '\a'};
        UINT16 length = sizeof(plaintext); // 这样无论末尾有没有'\0'都可以进行 RSA 加密
        printf("RSA 加密前: plaintext={");
        for (UINT16 i=0; i<length; i++)
        {
            if (isprint(plaintext[i]))
            {
                printf("'%c',", plaintext[i]);
            } else
            {
                printf("'\\0x%02x',", plaintext[i]);
            }
        }
        printf("}\n");

        printf("设置数据, 公钥的TPM句柄值以及加解密填充方案\n");
        encrypt.config(plaintext, length, RSAKeyBits, pubKeyHandle);

        printf("发送命令 RSA_Encrypt\n");
        framework.sendCommand(encrypt);
        framework.fetchResponse(encrypt);
        printf("RSA 加密命令执行完毕\n");

        // 分析 Encrypt 命令输出的密文
        struct {
            unsigned int size;
            const unsigned char *buffer;
        } ciphertext;

        ciphertext.size = encrypt.outDataLength();
        ciphertext.buffer = encrypt.outDataBuffer();

        printf("RSA 加密后密文为:\n");
        printf("---- BEGIN ----\n");
        for (UINT16 i=0; i<ciphertext.size; i++)
        {
            printf("%02X", ciphertext.buffer[i]);
            if ((i & 0x1F) == 0x1F)
            {
                printf("\n");
            }
        }
        printf("----- END -----\n");

        printf("设置数据, 解密私钥的TPM句柄值, 加解密填充方案\n");
        decrypt.config(ciphertext.buffer, ciphertext.size, RSAKeyBits, privkeyHandle);
        printf("提供 RSA 私钥访问授权值以及指定授权会话\n");
        decrypt.configAuthPassword(ChildPassword, ChildPasswordLen);
        decrypt.configAuthSession(TPM_RS_PW);

        printf("发送命令 RSA_Decrypt\n");
        framework.sendCommand(decrypt);
        framework.fetchResponse(decrypt);
        printf("RSA 解密命令执行完毕\n");

        // 分析 Decrypt 命令输出的明文
        struct {
            unsigned int size;
            const unsigned char *buffer;
        } result;

        result.size = decrypt.outDataLength();
        result.buffer = decrypt.outDataBuffer();

        printf("RSA 解密后: result={");

        for (UINT16 i=0; i<result.size; i++)
        {
            if (isprint(result.buffer[i]))
            {
                printf("'%c',", result.buffer[i]);
            } else
            {
                printf("'\\0x%02x',", plaintext[i]);
            }
        }
        printf("}\n");
    }
    catch (...)
    {
        fprintf(stderr, "Unknown Error\n");
    }
    printf("\n");

    ///////////////////////////////////////////////////////////////////////////
    printf("最后一步: 清理测试现场, 调用 Flush 命令清除密钥节点\n");
    TPMCommands::FlushLoadedKeyNode flush1;
    TPMCommands::FlushLoadedKeyNode flush2;
    try
    {
        flush1.configKeyNodeToFlushAway(createprimary.outObjectHandle());

        printf("发送命令, 让 TPM 删除 CreatePrimary 命令创建的主节点\n");
        framework.sendCommand(flush1);
        framework.fetchResponse(flush1);
        printf("flush1 成功删除了主节点\n");
    }
    catch (std::exception& e)
    {
        fprintf(stderr, "flush1: An error happened: %s\n", e.what());
    }
    catch (...)
    {
        fprintf(stderr, "Unknown error happened in TPM command FlushLoadedKeyNode\n");
    }
    try
    {
        flush2.configKeyNodeToFlushAway(load.outObjectHandle());

        printf("发送命令, 让 TPM 删除 Create/Load 命令输出的子节点\n");
        framework.sendCommand(flush2);
        framework.fetchResponse(flush2);
        printf("flush2 成功删除了子节点\n");
    }
    catch (std::exception& e)
    {
        fprintf(stderr, "flush2: An error happened: %s\n", e.what());
    }
    catch (...)
    {
        fprintf(stderr, "Unknown error happened in TPM command FlushLoadedKeyNode\n");
    }
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    // 测试结束需要手动切断与 TSS resource manager 之间的连接
    framework.disconnect();
}

static void SigningAndSignatureVerification_SubTest2(MyAppFramework& framework)
{
    printf("步骤一: 手动执行一条 Hash 命令, 输出一个哈希摘要值\n");
    const char szMessage[] = "abc";
    printf("SHA256 测试用例-1 szMessage[]: \"%s\", (共%d字节)\n", szMessage, (int)strlen(szMessage));
    printf("预期的 SHA256 哈希摘要={ba:78:16:bf:8f:01:cf:ea:41:41:40:de:5d:ae:22:23:b0:03:61:a3:96:17:7a:9c:b4:10:ff:61:f2:00:15:ad}\n");
    TPMCommands::Hash hash;
    try
    {
        hash.configHashAlgorithmUsingSHA256();
        hash.configInputData(szMessage, strlen(szMessage));

        printf("发送 Hash 命令\n");
        framework.sendCommand(hash);
        framework.fetchResponse(hash);

        printf("取回 SHA256 摘要结果如下:\n");
        const TPM2B_DIGEST& digest = hash.outHash();
        printf("digest.t.size=%d\n", digest.t.size);
        printf("digest.t.data={");
        if (digest.t.size >= 1)
        {
            int size = digest.t.size;
            int last = size-1;
            for (int i=0; i<=size-2; i++)
            {
                printf("%02x:", digest.t.buffer[i]);
            }
            printf("%02x", digest.t.buffer[last]);
        }
        printf("}\n");
    }
    catch (...)
    {
        fprintf(stderr, "Unknown Error\n");
    }
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    printf("步骤二: 调用 CreatePrimary 命令, 生成一个主节点(Primary 节点)\n");
    TPMCommands::CreatePrimary createprimary;
    const char *primaryPassword = "abcd";
    const UINT16 primaryPasswordLen = strlen(primaryPassword);
    try
    {
        TPMT_PUBLIC publicArea;

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
        publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
        publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
        publicArea.parameters.rsaDetail.keyBits = 2048;
        publicArea.parameters.rsaDetail.exponent = 0;
        publicArea.unique.rsa.t.size = 0;
        if (TPM_ALG_RSA == publicArea.type)
        {
            printf("Key type: RSA.\n");
            printf("Key size: %d bits.\n", publicArea.parameters.rsaDetail.keyBits);
        }
        createprimary.configPublicData(publicArea);

        const TPMI_RH_HIERARCHY hierarchy = TPM_RH_OWNER;
        if (TPM_RH_NULL == hierarchy)
        {
            printf("We will create a new key in TPM NULL-hierarchy.\n");
        }
        else if (TPM_RH_OWNER == hierarchy)
        {
            printf("We will create a new key in TPM Storage-hierarchy(TPM_RH_OWNER).\n");
        }
        createprimary.configAuthHierarchy(hierarchy);
        createprimary.configAuthSession(TPM_RS_PW);
        createprimary.configAuthPassword("", 0);
        createprimary.configKeyNameAlg(TPM_ALG_SHA1); // 备注: 前面已经设置过一次 "publicArea.nameAlg = TPM_ALG_SHA1;" 重复设置应该没有问题
        createprimary.configKeySensitiveData(primaryPassword, primaryPasswordLen, "", 0);

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
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    printf("步骤三: 组合调用 Create 和 Load 命令, 在主节点下加载密钥子节点\n");
    TPMCommands::Create create;
    TPMCommands::Load load;
    const char *ChildPassword = "child password";
    const UINT16 ChildPasswordLen = strlen("child password");
    try
    {
        printf("We will create a child key node under parent(0x%08X).\n",
                createprimary.outObjectHandle());
        create.configAuthParent(createprimary.outObjectHandle());
        create.configAuthSession(TPM_RS_PW);
        create.configAuthPassword(primaryPassword, primaryPasswordLen);
        create.configKeySensitiveData(ChildPassword, ChildPasswordLen, "", 0);
        TPM2B_PUBLIC inPublic;
        {
            inPublic.t.publicArea.type = TPM_ALG_RSA;
            inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;
            inPublic.t.publicArea.objectAttributes.val = 0;
            inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
            inPublic.t.publicArea.objectAttributes.fixedParent = 1;
            inPublic.t.publicArea.objectAttributes.restricted = 0; // 必须清除 restricted 标志位. 原因未知, 需要进一步研究
            inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
            inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
            inPublic.t.publicArea.objectAttributes.decrypt = 0;
            inPublic.t.publicArea.objectAttributes.sign = 1; // 单独设置属性签名密钥
            inPublic.t.publicArea.authPolicy.t.size = 0;
            inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
            inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
            inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
            inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
            inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
            inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
            inPublic.t.publicArea.unique.rsa.t.size = 0;
            if (TPM_ALG_RSA == inPublic.t.publicArea.type)
            {
                printf("Key type: RSA.\n");
                printf("Key size: %d bits.\n", inPublic.t.publicArea.parameters.rsaDetail.keyBits);
            }
        }
        create.configPublicData(inPublic);

        framework.sendCommand(create);
        framework.fetchResponse(create);
        printf("Child key node has been created successfully.\n");

        load.configAuthParent(createprimary.outObjectHandle());
        load.configAuthSession(TPM_RS_PW);
        load.configAuthPassword(primaryPassword, primaryPasswordLen);
        load.configPrivateData(create.outPrivate());
        load.configPublicData(create.outPublic());

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
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    printf("步骤四: 测试 Sign 命令\n");
    printf("这里将重复多轮测试检查使用 RSA-PSS 签名方案时的签名输出值.\n");
    printf("(RSA-PSS 签名方案特点是对同一输入进行若干次 RSA 签名, 每次的输出将随机发生变化, 提高安全性). 方案代码TPM_ALG_RSAPSS=0x%04X\n", TPM_ALG_RSAPSS);
    const int TOTAL = 3;
    TPMCommands::Sign sign[3];
    TPM_HANDLE signingKey = load.outObjectHandle();
    try
    {
        const TPM2B_DIGEST& digest = hash.outHash();
        const TPMT_TK_HASHCHECK& ticket = hash.outValidationTicket();

        printf("步骤 4.1: 实验组 i=0\n");
        sign[0].configDigestToBeSigned(digest.t.buffer, digest.t.size);
        sign[0].configValidationTicket(ticket);
        sign[0].configScheme(DigitalSignatureSchemes::RSAPSS_SHA256);
        sign[0].configSigningKey(signingKey);
        sign[0].configAuthPassword(ChildPassword, ChildPasswordLen);
        sign[0].configAuthSession(TPM_RS_PW);

        framework.sendCommand(sign[0]);
        framework.fetchResponse(sign[0]);

        // 分析 Sign 命令输出的数字签名
        const TPMT_SIGNATURE& out0 = sign[0].outSignature();
        printf("sigAlg=0x%04X (备注: TPM_ALG_RSAPSS=0x%04X)\n", out0.sigAlg, TPM_ALG_RSAPSS);
        printf("hashAlg=0x%04X (备注: TPM_ALG_SHA1=0x%04X,  TPM_ALG_SHA256=0x%04X)\n", out0.signature.any.hashAlg, TPM_ALG_SHA1, TPM_ALG_SHA256);
        if (out0.sigAlg == TPM_ALG_RSAPSS)
        {
            const BYTE *buffer = out0.signature.rsapss.sig.b.buffer;
            const UINT16 size =  out0.signature.rsapss.sig.b.size;
            printf("数字签名 size=%d\n", size);
            for (UINT16 i = 0; i < size; i++)
            {
                printf("%02X", buffer[i]);
                if ((i & 0x1F) == 0x1F)
                {
                    printf("\n");
                }
            }
            printf("\n");
        }

        printf("\n");
        printf("步骤 4.2: 对照组 i>=1 && i<=%d\n", TOTAL-1);
        printf("重复进行多次数字签名, 作为对照组. 检查每次输出的数字签名值是否相同\n");
        printf("预期结果: 每次输出的数字签名各不相同\n");
        printf("\n");
        for (int i = 1; i < TOTAL; i++)
        {
            sign[i].configDigestToBeSigned(digest.t.buffer, digest.t.size);
            sign[i].configValidationTicket(ticket);
            sign[i].configScheme(DigitalSignatureSchemes::RSAPSS_SHA256);
            sign[i].configSigningKey(signingKey);
            sign[i].configAuthPassword(ChildPassword, ChildPasswordLen);
            sign[i].configAuthSession(TPM_RS_PW);

            framework.sendCommand(sign[i]);
            framework.fetchResponse(sign[i]);

            // 打印第二条命令输出的数字签名
            const TPMT_SIGNATURE& out = sign[i].outSignature();
            if (out.sigAlg == TPM_ALG_RSAPSS)
            {
                const BYTE *buffer = out.signature.rsapss.sig.b.buffer;
                const UINT16 size =  out.signature.rsapss.sig.b.size;
                printf("对照组i=%d: 数字签名 size=%d\n", i, size);
                for (UINT16 i = 0; i < size; i++)
                {
                    printf("%02X", buffer[i]);
                    if ((i & 0x1F) == 0x1F)
                    {
                        printf("\n");
                    }
                }
                printf("\n");
            }
        }

        printf("\n");
        printf("步骤五: 依次对每组输出的签名进行校验, 共%d组, [0<=i<=%d]\n", TOTAL, TOTAL-1);
        for (int i = 0; i < TOTAL; i++)
        {
            const TPMT_SIGNATURE& signature = sign[i].outSignature();
            const BYTE *buffer = signature.signature.rsapss.sig.b.buffer;
            printf("第i=%d组签名值=0x%02X%02X%02X%02X...\n", i, buffer[0], buffer[2], buffer[1], buffer[3]);
            try
            {
                TPMCommands::VerifySignature verifysignature;
                verifysignature.configSigningKey(signingKey);
                verifysignature.configDigestWithSignature(digest, signature);

                framework.sendCommand(verifysignature);
                framework.fetchResponse(verifysignature);

                printf("数字签名校验的结果: 有效\n");
            }
            catch (TSS2_RC rc)
            {
                TSS2_RC mask1 = TSS2_ERROR_LEVEL_MASK; // 错误级别掩码
                TSS2_RC mask2 = (0xFF - TPM_RC_P); // TPM 级别应答码详细错误码
                if ((TSS2_TPM_ERROR_LEVEL == (rc & mask1)) && (TPM_RC_SIGNATURE == (rc & mask2)))
                {
                    printf("发现数字签名不匹配, TPM_RC_SIGNATURE(0x%X), rc=0x%X\n", TPM_RC_SIGNATURE, rc);
                    printf("TPM_RC_SIGNATURE(0x%X)\n", TPM_RC_SIGNATURE);
                }
                else
                {
                    fprintf(stderr, "TPM has returned a unknown error response code 0x%X\n", rc);
                    fprintf(stderr, "Please try to run \"tpm2_rc_decode 0x%X\" to see more details.\n", rc);
                }
            }
        }
    }
    catch (...)
    {
        fprintf(stderr, "Unknown Error\n");
    }
    printf("\n");
    ///////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////
    printf("最后一步: 清理测试现场, 调用 Flush 命令清除密钥节点\n");
    TPMCommands::FlushLoadedKeyNode flush1;
    TPMCommands::FlushLoadedKeyNode flush2;
    try
    {
        flush1.configKeyNodeToFlushAway(createprimary.outObjectHandle());

        printf("发送命令, 让 TPM 删除 CreatePrimary 命令创建的主节点\n");
        framework.sendCommand(flush1);
        framework.fetchResponse(flush1);
        printf("flush1 成功删除了主节点\n");
    }
    catch (std::exception& e)
    {
        fprintf(stderr, "flush1: An error happened: %s\n", e.what());
    }
    catch (...)
    {
        fprintf(stderr, "Unknown error happened in TPM command FlushLoadedKeyNode\n");
    }
    try
    {
        flush2.configKeyNodeToFlushAway(load.outObjectHandle());

        printf("发送命令, 让 TPM 删除 Create/Load 命令输出的子节点\n");
        framework.sendCommand(flush2);
        framework.fetchResponse(flush2);
        printf("flush2 成功删除了子节点\n");
    }
    catch (std::exception& e)
    {
        fprintf(stderr, "flush2: An error happened: %s\n", e.what());
    }
    catch (...)
    {
        fprintf(stderr, "Unknown error happened in TPM command FlushLoadedKeyNode\n");
    }
    printf("\n");
}

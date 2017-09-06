/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <cstdio>
#include <cstdlib>
#include <cassert>
using namespace std;

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#ifndef DEFAULT_RESMGR_TPM_PORT /* @note This mircro and the legacy resourcemgr has been removed by upstream developer since 2017-05-09. @see https://github.com/01org/TPM2.0-TSS/commit/7966ef8916f79ed09eab966a58d773f413fbb67f#diff-9b5d40e51314bbf4fdfc0997a4b58838L41 */
    #warning // DEFAULT_RESMGR_TPM_PORT was removed from <tcti_socket.h>!
    #warning // You should either use "tcti/tcti-tabrmd.h" (which is a replacement to the legacy resourcemgr), or directly connect to port 2321 of the simulator without a resourcemgr!
    #warning // See https://github.com/01org/tpm2-abrmd
    #include <stdint.h>
    const uint16_t DEFAULT_RESMGR_TPM_PORT=DEFAULT_SIMULATOR_TPM_PORT;
#endif
#include "TPMCommand.h"
#include "ConnectionManager.h"
#include "SocketConnectionManager.h"
#include "Base64Converter.h"

// 内部函数原型声明
static void TestRSAStorageKeyBuilderClient(ConnectionManager& connectionManager);
static void TestTPMNodeRestoringClient(ConnectionManager& connectionManager);

/* 排版格式: 以下函数均使用4个空格缩进，不使用Tab缩进 */

static void PrintHelp()
{
    printf("用法:\n");
    printf("-rmhost 手动指定运行资源管理器(即 resourcemgr)的主机IP地址或主机名 (默认值: %s)\n",
            DEFAULT_HOSTNAME);
    printf("-rmport 手动指定运行资源管理器的主机端口号 (默认值: %d)\n", DEFAULT_RESMGR_TPM_PORT);
    printf("-localTctiTest\n");
    printf("[注意: 若使用 -localTctiTest 请手动关闭任何占用/dev/tpm0设备的进程, 即: 关闭其他直接访问/dev/tpm0的resourcemgr进程]\n");
}

int main(int argc, char *argv[])
{
    int count;
    int usingDeviceFile = false;
    const char *deviceFile = "/dev/tpm0";
    const char *hostname = "127.0.0.1";
    uint16_t port = DEFAULT_RESMGR_TPM_PORT;

    count = 1;
    while (count < argc)
    {
        if( 0 == strcmp(argv[count], "-localTctiTest" ) )
        {
            usingDeviceFile = true;
            count += 1;
            // 以上代码提供的命令行参数为: -localTctiTest
            // 用于直接操作/dev/tpm0设备
            continue;
        }

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

    SocketConnectionManager socketConnectionManager(hostname, port);
    CharacterDeviceConnectionManager deviceConnectionManager(deviceFile);

    ConnectionManager *connectionManager; ///< 通过指针选择使用哪一个上下文初始化器
    connectionManager = &socketConnectionManager; // 默认优先使用socket连接(2323端口上的resourcemgr或2321端口上的Simulator)
    if (usingDeviceFile)
    {
        connectionManager = &deviceConnectionManager;
    }
    connectionManager->connect();
    TestRSAStorageKeyBuilderClient(*connectionManager);
    TestTPMNodeRestoringClient(*connectionManager);
    connectionManager->disconnect();

    return (0);
}

///////////////////////////////////////////////////////////////////////////////

#include <stdexcept>
using std::exception;
#include "Client.h"
#include "ContextFileFormatter.h"

static void TestRSAStorageKeyBuilderClient(ConnectionManager& connectionManager)
{
    class RSAStorageKeyBuilderClient: public Client
    {
    public:
        /// Hierarchy
        ///
        /// 备选值:
        /// - 0x40000007 TPM_RH_NULL
        /// - 0x4000000B TPM_RH_ENDORSEMENT
        /// - 0x4000000C TPM_RH_PLATFORM
        /// - 0x40000001 TPM_RH_OWNER
        TPMI_RH_HIERARCHY hierarchy;
        const void *hierarchyPassword;
        UINT16 hierarchyPasswordLen;

    public:
        /// Hash algorithm for key name (it is required by TPM)
        ///
        /// 备选值:
        /// - 0x0004 TPM_ALG_SHA1
        /// - 0x000B TPM_ALG_SHA256
        /// - 0x000C TPM_ALG_SHA384
        /// - 0x000D TPM_ALG_SHA512
        /// - 0x0012 TPM_ALG_SM3_256
        /// - 0x0027 TPM_ALG_SHA3_256
        /// - 0x0028 TPM_ALG_SHA3_384
        /// - 0x0029 TPM_ALG_SHA3_512
        TPMI_ALG_HASH nameAlg;

    public:
        TPMI_RSA_KEY_BITS keyBits; /// 单位: bit. 可选取值: 1024, 2048

    public:
        UINT32 exponent; ///< 公钥指数e. 可选取值: 2, 3, 5, 17, 257, 65537 或 0. 取 0 时表示使用TPM默认值 65537

    public:
        RSAStorageKeyBuilderClient()
        {
            hierarchy=TPM_RH_NULL;
            hierarchyPassword = (const void *) "";
            hierarchyPasswordLen = strlen((const char *) hierarchyPassword);
            nameAlg=TPM_ALG_SHA1;
            keyBits = 2048;
            exponent = (UINT32) 0; // 公钥指数e. 可选取值: 2, 3, 5, 17, 257, 65537 或 0. 取 0 时表示使用TPM默认值 65537
        }
    public:
        ~RSAStorageKeyBuilderClient()
        {
        }

    private:
        TPMCommands::ContextSave contextSave;

    public:
        void generatePrimaryRSAStorageKey()
        {
            TPMCommands::CreatePrimary createPrimaryNode;
            TPMCommands::FlushLoadedKeyNode flushPrimaryNode;
            try
            {
                createPrimaryNode.configAuthHierarchy(hierarchy);
                createPrimaryNode.configAuthSession(TPM_RS_PW);
                createPrimaryNode.configAuthPassword("", 0);
                createPrimaryNode.configKeyNameAlg(TPM_ALG_SHA1); // 备注: 前面已经设置过一次 "publicArea.nameAlg = TPM_ALG_SHA1;" 重复设置应该没有问题

                const char *primaryPassword = "";
                const UINT16 primaryPasswordLen = strlen(primaryPassword);
                createPrimaryNode.configKeySensitiveData(primaryPassword, primaryPasswordLen, "", 0);

                TPMT_PUBLIC publicArea;
                TPMI_ALG_PUBLIC type;
                type = TPM_ALG_RSA;
                publicArea.type = type;
                publicArea.nameAlg = nameAlg;
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
                publicArea.parameters.rsaDetail.keyBits = keyBits; // 长度位数
                publicArea.parameters.rsaDetail.exponent = exponent; // 公钥指数e
                publicArea.unique.rsa.t.size = 0;
                if (TPM_ALG_RSA == type)
                {
                    printf("Key type: RSA.\n");
                    printf("Key size: %d bits.\n", publicArea.parameters.rsaDetail.keyBits);
                }

                if (TPM_RH_NULL == hierarchy)
                {
                    printf("We will create a new key in TPM NULL-hierarchy.\n");
                }
                else if (TPM_RH_OWNER == hierarchy)
                {
                    printf("We will create a new key in TPM Storage-hierarchy(TPM_RH_OWNER).\n");
                }
                createPrimaryNode.configPublicData(publicArea);

                sendCommand(createPrimaryNode);
                fetchResponse();

                printf("New primary key created successfully! Handle=0x%8.8x\n", createPrimaryNode.outObjectHandle());
                const TPM2B_NAME& keyName = createPrimaryNode.outName();
                printf("keyName.t.size=%d\n", keyName.t.size);
                printf("keyName data: ");
                for (size_t i=0; i<keyName.t.size; i++)
                {
                    printf("0x%02X,", keyName.t.name[i]);
                }
                printf("\n");

                printf("发送一条 ContextSave 命令, 让 TPM 备份 CreatePrimary 命令创建的主节点的上下文到 TPM 外部\n");
                contextSave.configHandle(createPrimaryNode.outObjectHandle());
                sendCommand(contextSave);
                fetchResponse();
                printf("ContextSave 命令执行成功\n");
                printf("blob data: ");
                const TPMS_CONTEXT& blob = contextSave.outContext();
                for (size_t i=0; i<blob.contextBlob.b.size; i++)
                {
                    printf("%02X", blob.contextBlob.b.buffer[i]);
                }
                printf("\n");

                printf("进行清理工作\n");
                try
                {
                    flushPrimaryNode.configKeyNodeToFlushAway(createPrimaryNode.outObjectHandle());

                    printf("发送 FlushContext 命令, 让 TPM 删除 CreatePrimary 命令创建的主节点\n");
                    sendCommand(flushPrimaryNode);
                    fetchResponse();
                    printf("flushPrimaryNode 成功删除了主节点\n");
                } catch (std::exception& e)
                {
                    fprintf(stderr, "flushPrimaryNode: An error happened: %s\n", e.what());
                } catch (...)
                {
                    fprintf(stderr, "Unknown error happened in TPM command FlushLoadedKeyNode\n");
                }
            } catch (std::exception& e)
            {
                fprintf(stderr, "RSAStorageKeyBuilderClient::generatePrimaryRSAStorageKey(): An error happened: %s\n", e.what());
            }
        }

        const TPMS_CONTEXT& getNodeContext()
        {
            return (contextSave.outContext());
        }
    };


    RSAStorageKeyBuilderClient client;
    client.bind(connectionManager);
    try
    {
        client.hierarchy = TPM_RH_OWNER;
        client.generatePrimaryRSAStorageKey();

        ContextFileFormatter formatter;
        try
        {
            formatter.setFileName("PrimaryNodeContext.csv");
            formatter.output(client.getNodeContext());
        } catch (...)
        {
        }
    } catch (...)
    {
    }
    client.unbind();
}

///////////////////////////////////////////////////////////////////////////////

#include <stdexcept>
using std::exception;
#include "Client.h"
#include "ContextFileParser.h"

static void TestTPMNodeRestoringClient(ConnectionManager& connectionManager)
{
    class TPMNodeRestoringClient: public Client
    {
    public:
        TPM_HANDLE restoreNode(const TPMS_CONTEXT& nodeContext)
        {
            TPM_HANDLE handle;
            try
            {
                TPMCommands::ContextLoad contextLoad;
                contextLoad.configContext(nodeContext);
                printf("发送 ContextLoad 命令\n");
                sendCommand(contextLoad);
                printf("等待应答桢\n");
                fetchResponse();
                printf("已收到应答桢\n");
                handle = contextLoad.outHandle();
            } catch (std::exception& e)
            {
                fprintf(stderr, "TPMNodeRestoringClient::generatePrimaryRSAStorageKey(): An error happened: %s\n", e.what());
            }
            return (handle);
        }
    };

    class TPMNodeFlushingClient: public Client
    {
    public:
        void flushNode(TPM_HANDLE handle)
        {
            TPMCommands::FlushLoadedKeyNode flush;
            try
            {
                flush.configKeyNodeToFlushAway(handle);

                printf("发送 FlushContext 命令, 让 TPM 删除节点 0x%08X\n", (int)handle);
                sendCommand(flush);
                fetchResponse();
                printf("已经成功删除了节点\n");
            } catch (std::exception& e)
            {
                fprintf(stderr, "flushPrimaryNode: An error happened: %s\n", e.what());
            } catch (...)
            {
                fprintf(stderr, "Unknown error happened in TPM command FlushLoadedKeyNode\n");
            }

        }
    };

    TPMS_CONTEXT nodeContext;
    ContextFileParser parser;

    parser.setFileName("PrimaryNodeContext.csv");
    parser.fetch(nodeContext);

    TPM_HANDLE handle;
    {
        TPMNodeRestoringClient client;
        client.bind(connectionManager);
        handle = client.restoreNode(nodeContext);
        client.unbind();
        printf("new handle = 0x%08X\n", handle);
    }

    {
        TPMNodeFlushingClient client;
        client.bind(connectionManager);
        client.flushNode(handle);
        client.unbind();
    }
}

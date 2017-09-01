/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <cstdio>
#include <errno.h>
#include <vector>
using std::vector;
#include <stdexcept>
using std::exception;

#include <tcti/tcti_socket.h>
#define DEFAULT_RESMGR_TPM_PORT 2323
#ifndef DEFAULT_RESMGR_TPM_PORT /* @note This mircro and the legacy resourcemgr has been removed by upstream developer since 2017-05-09. @see https://github.com/01org/TPM2.0-TSS/commit/7966ef8916f79ed09eab966a58d773f413fbb67f#diff-9b5d40e51314bbf4fdfc0997a4b58838L41 */
    #warning // DEFAULT_RESMGR_TPM_PORT was removed from <tcti_socket.h>!
    #warning // You should either use "tcti/tcti-tabrmd.h" (which is a replacement to the legacy resourcemgr), or directly connect to port 2321 of the simulator without a resourcemgr!
    #warning // See https://github.com/01org/tpm2-abrmd
    #include <stdint.h>
    const uint16_t DEFAULT_RESMGR_TPM_PORT=DEFAULT_SIMULATOR_TPM_PORT;
#endif

#include "Client.h"
#include "CalculatorClient.h"
#include "ConnectionManager.h"
#include "SocketConnectionManager.h"

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
    CharacterDeviceConnectionManager charDevConnectionManager(deviceFile);

    ConnectionManager *connectionManager; ///< 通过指针选择使用哪一个上下文初始化器

    connectionManager = &socketConnectionManager; // 默认优先使用socket TCTI 连接2323端口上的resourcemgr或2321端口上的Simulator
    if (usingDeviceFile)
    {
        connectionManager = &charDevConnectionManager;
    }
    connectionManager->connect();

    /* 测试 FileHashCalculatorClient */
    const char *szFilename=NULL;
    FILE *fp;
    if (!szFilename)
    {
        fp = stdin;
    } else
    {
        fp = fopen(szFilename, "rb");
    }
    if (!fp)
    {
        fprintf(stderr, "Error: Cannot open file \"%s\"\n", strerror(errno));
        goto DISCONNECT;
    }

    try
    {
        FileHashCalculatorClient calc;
        calc.bind(*connectionManager);
        const vector<BYTE>& digest = calc.SHA1(fp);
        calc.unbind();
        {
            vector<BYTE>::const_iterator i;
            for (i=digest.begin(); i!=digest.end(); i++)
            {
                printf("%02X", (BYTE) *i);
            }
            printf("\n");
        }
    } catch (std::exception err)
    {
        fprintf(stderr, "Error: %s\n", err.what());
    }


DISCONNECT:
    connectionManager->disconnect();

    return (0);
}

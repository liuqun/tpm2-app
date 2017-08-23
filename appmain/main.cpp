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
    #warning // You should either use "tcti/tcti-tabrmd.h" (which is a replacement to the legacy resourcemgr), or directly connect to port 2321 of the simulator without a resourcemgr!
    #warning // See https://github.com/01org/tpm2-abrmd
    #include <stdint.h>
    const uint16_t DEFAULT_RESMGR_TPM_PORT=DEFAULT_SIMULATOR_TPM_PORT;
#endif
#include "TPMCommand.h"
#include "Client.h"
#include "CalculatorClient.h"

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

#include <vector>
using std::vector;
#include <string>
using std::string;
#include <sstream>
using std::stringstream;
#include <stdexcept>
using std::exception;
using std::runtime_error;

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

    SocketBasedClientContextInitializer socketTCTIContextInitializer(hostname, port);
    DeviceBasedClientContextInitializer deviceTCTIContextInitializer(deviceFile);

    ClientContextInitializer *pInitializer; ///< 通过指针选择使用哪一个上下文初始化器

    pInitializer = &socketTCTIContextInitializer;
    if (usingDeviceFile)
    {
        pInitializer = &deviceTCTIContextInitializer;
    }

    /* HMAC 测试 */
    {
        HMACCalculatorClient client;
        client.setContextInitializer(*pInitializer);

        try
        {
            client.connect();

            // 一组 HMAC-SHA-1 测试数据, 来自 https://tools.ietf.org/html/rfc2202#section-3
            const char *Data = "Hi There";
            const uint16_t nDataLen = strlen(Data);
            const BYTE HmacKey[] = {
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
            };
            const uint16_t nHmacKeyLen = sizeof(HmacKey);
            printf("【HMAC-SHA1 测试用例1】\n");
            printf("测试数据取自RFC-2202 https://tools.ietf.org/html/rfc2202#section-3\n");
            printf("输入明文消息为: \"%s\" 长度: %d字节\n", Data, nDataLen);
            printf("输入对称密钥为: \n");
            for (UINT16 i=0; i<nHmacKeyLen; i++)
            {
                printf("%02X:", HmacKey[i]);
            }
            printf("\n");
            printf("预期HMAC输出结果: %s\n", "b6:17:31:86:55:05:72:64:e2:8b:c0:b6:fb:37:8c:8e:f1:46:be:00");

            {
                const std::vector<BYTE>& digest =
                        client.HMAC_SHA1(Data, nDataLen, HmacKey, nHmacKeyLen);
                printf("实际HMAC输出结果: ");
                vector<BYTE>::const_iterator i;
                for (i=digest.begin(); i!=digest.end(); i++)
                {
                    printf("%02X:", (BYTE) *i);
                }
                printf("\n");
            }

            client.disconnect();
        }
        catch (std::exception& err)
        {
            fprintf(stderr, "Error: %s\n", err.what());
            PrintHelp();
        }

        try
        {
            client.connect();

            // 一组 HMAC-SHA-256 测试数据, 来自https://tools.ietf.org/html/rfc4231#section-4
            const char *Data = "Hi There";
            const uint16_t nDataLen = strlen(Data);
            const BYTE HmacKey[20] = {
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
            };
            const uint16_t nHmacKeyLen = sizeof(HmacKey);
            printf("【HMAC-SHA256 测试用例】\n");
            printf("测试数据取自RFC-4231 https://tools.ietf.org/html/rfc4231#section-4\n");
            printf("输入明文消息为: \"%s\" 长度: %d字节\n", Data, nDataLen);
            printf("输入对称密钥为: \n");
            for (UINT16 i=0; i<nHmacKeyLen; i++)
            {
                printf("%02X:", HmacKey[i]);
            }
            printf("\n");
            printf("预期HMAC输出结果: %s\n", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

            {
                const std::vector<BYTE>& digest =
                        client.HMAC_SHA256(Data, nDataLen, HmacKey, nHmacKeyLen);
                printf("实际HMAC输出结果: ");
                vector<BYTE>::const_iterator i;
                for (i=digest.begin(); i!=digest.end(); i++)
                {
                    printf("%02X", (BYTE) *i);
                }
                printf("\n");
            }

            client.disconnect();
        }
        catch (std::exception& err)
        {
            fprintf(stderr, "Error: %s\n", err.what());
            PrintHelp();
        }
    }

    /* HMAC 多桢序列测试 */
    {
        HMACSequenceScheduler scheduler;
        scheduler.setContextInitializer(*pInitializer);
        try
        {
            scheduler.connect();

            // 一组 HMAC-SHA-1 测试数据, 来自 https://tools.ietf.org/html/rfc2202#section-3
            const char *Data = "Hi There";
            const uint16_t nDataLen = strlen(Data);
            const BYTE HmacKey[20] = {
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
            };
            const uint16_t nHmacKeyLen = sizeof(HmacKey);
            printf("【HMAC-SHA1 测试用例1】\n");
            printf("测试数据取自RFC-2202 https://tools.ietf.org/html/rfc2202#section-3\n");
            printf("输入明文消息为: \"%s\" 长度: %d字节\n", Data, nDataLen);
            printf("输入对称密钥为: \n");
            for (UINT16 i=0; i<nHmacKeyLen; i++)
            {
                printf("%02X:", HmacKey[i]);
            }
            printf("\n");
            printf("预期HMAC输出结果: %s\n", "b6:17:31:86:55:05:72:64:e2:8b:c0:b6:fb:37:8c:8e:f1:46:be:00");
            printf("实际HMAC输出结果: \n");
            {
                scheduler.start(TPM_ALG_SHA1, HmacKey, nHmacKeyLen);
                scheduler.inputData(Data, nDataLen);
                scheduler.complete();
                const TPM2B_DIGEST& hmac = scheduler.outHMAC();
                for (UINT16 i=0; i<hmac.t.size; i++)
                {
                    printf("%02X:", hmac.t.buffer[i]);
                }
                printf("\n");
            }
            scheduler.disconnect();
        }
        catch (std::exception& err)
        {
            fprintf(stderr, "Error: %s\n", err.what());
            PrintHelp();
        }

        try
        {
            scheduler.connect();

            // 一组 HMAC-SHA-256 测试数据, 来自https://tools.ietf.org/html/rfc4231#section-4
            const char *Data = "Hi There";
            const uint16_t nDataLen = strlen(Data);
            const BYTE HmacKey[20] = {
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
                0x0b, 0x0b, 0x0b, 0x0b,
            };
            const uint16_t nHmacKeyLen = sizeof(HmacKey);
            printf("【HMAC-SHA256 测试用例】\n");
            printf("测试数据取自RFC-4231 https://tools.ietf.org/html/rfc4231#section-4\n");
            printf("输入明文消息为: \"%s\" 长度: %d字节\n", Data, nDataLen);
            printf("输入对称密钥为: \n");
            for (UINT16 i=0; i<nHmacKeyLen; i++)
            {
                printf("%02X:", HmacKey[i]);
            }
            printf("\n");
            printf("预期HMAC输出结果: %s\n", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
            printf("实际HMAC输出结果: \n");
            {
                scheduler.start(TPM_ALG_SHA256, HmacKey, nHmacKeyLen);
                scheduler.inputData(Data, nDataLen);
                scheduler.complete();
                const TPM2B_DIGEST& hmac = scheduler.outHMAC();
                for (UINT16 i=0; i<hmac.t.size; i++)
                {
                    printf("%02X", hmac.t.buffer[i]);
                }
                printf("\n");
            }
            scheduler.disconnect();
        }
        catch (std::exception& err)
        {
            fprintf(stderr, "Error: %s\n", err.what());
            PrintHelp();
        }
    }

    return (0);
}

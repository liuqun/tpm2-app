/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <cstdio>
#include <cstdlib>
using namespace std;

#include <sapi/tpm20.h>

#include "debug.h"
#include "tcti_util.h"
#include "HashSequenceScheduler.h"

/* 自定义函数 */
static void DoMyTestsWithTctiContext(TSS2_TCTI_CONTEXT *pTctiContext);
static void DoMyTestsWithSysContext(TSS2_SYS_CONTEXT *pSysContext);
static void RunDefaultTestCase(TSS2_SYS_CONTEXT *pSysContext);

/* 以下函数均使用4个空格缩进，不使用Tab缩进 */

static void PrintHelp()
{
    printf("用法:\n");
    printf("-rmhost 手动指定运行资源管理器(即 resourcemgr)的主机IP地址或主机名 (默认值: %s)\n",
            DEFAULT_HOSTNAME);
    printf("-rmport 手动指定运行资源管理器的主机端口号 (默认值: %d)\n", DEFAULT_RESMGR_TPM_PORT);
}

int main(int argc, char *argv[])
{
    TSS2_RC rval;
    TCTI_SOCKET_CONF rmInterfaceConfig;
    TSS2_TCTI_CONTEXT *pTctiContext;
    int count;

    rmInterfaceConfig.hostname = DEFAULT_HOSTNAME;
    rmInterfaceConfig.port = DEFAULT_RESMGR_TPM_PORT;
    rmInterfaceConfig.logCallback = DebugPrintfCallback;
    rmInterfaceConfig.logBufferCallback = DebugPrintBufferCallback;
    rmInterfaceConfig.logData = NULL;

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
            rmInterfaceConfig.hostname = argv[count + 1];  // 暂时不检查无效的输入参数
            count += 2;
        }
        else if (0 == strcmp(argv[count], "-rmport"))
        {
            if (count + 1 >= argc)
            {
                PrintHelp();
                return 1;
            }
            rmInterfaceConfig.port = strtoul(argv[count + 1], NULL, 10); // 暂时不检查无效的输入参数
            count += 2;
        }
        else
        {
            PrintHelp();
            return -1;
        }
    }
    // 以上代码提供了一组简单的命令行参数便于调试:
    // 其中包括 [-rmhost IP地址] 和 [-rmport 端口号]
    // 如果不指定命令行参数, 则会直接连接到本机 IP 地址默认端口上运行的资源管理器

    /**/
    rval = InitSocketTctiContext(&rmInterfaceConfig, &pTctiContext);
    if (rval != TSS2_RC_SUCCESS)
    {
        // Note:
        // 当前 InitSocketTcti() 返回的 TSS2_RC 值并未严格按照 TPM2.0 规范指示错误原因。
        // 错误返回值实测结果: 无法连接服务器端 IP 地址或默认端口号无法建立套接字时, 返回值均等于 1
        DebugPrintf(NO_PREFIX,
                "TCTI context initialization failed with error return code=0x%x\n",
                rval);
        return (-1);
    }
    else if (!pTctiContext)
    {
        DebugPrintf(NO_PREFIX, "TCTI context initialization failed\n");
        return (-1);
    }

    /* 使用前面创建的 TCTI 上下文对象进一步创建其他测试内容 */
    DoMyTestsWithTctiContext(pTctiContext);

    /* 测试结束后销毁 TCTI 上下文对象 */
    TeardownTctiContext(&pTctiContext);
    return (0);
}

static void DoMyTestsWithTctiContext(TSS2_TCTI_CONTEXT *pTctiContext)
{
    TSS2_RC rval;
    TSS2_ABI_VERSION abiVersion;
    TSS2_SYS_CONTEXT *pSysContext;
    size_t contextSize;

    contextSize = Tss2_Sys_GetContextSize(0);
    pSysContext = (TSS2_SYS_CONTEXT *) malloc(contextSize);
    if (!pSysContext)
    {
        DebugPrintf(NO_PREFIX,
                "Unable to allocate enough memory: malloc() failed.\n");
        DebugPrintf(NO_PREFIX, "Exiting...\n");
        return;
    }

    abiVersion.tssCreator = TSSWG_INTEROP;
    abiVersion.tssFamily = TSS_SAPI_FIRST_FAMILY;
    abiVersion.tssLevel = TSS_SAPI_FIRST_LEVEL;
    abiVersion.tssVersion = TSS_SAPI_FIRST_VERSION;

    rval = Tss2_Sys_Initialize(pSysContext, contextSize, pTctiContext,
            &abiVersion);

    if (rval != TSS2_RC_SUCCESS)
    {
        free(pSysContext);
        DebugPrintf(NO_PREFIX,
                "Unable to initialize system level API context:");
        DebugPrintf(NO_PREFIX,
                "Tss2_Sys_Initialize() returns error code 0x%06X.\n", rval);
        DebugPrintf(NO_PREFIX, "Exiting...\n");
        return;
    }

    DoMyTestsWithSysContext(pSysContext);

    /* Clean up the context when all tests ends */
    Tss2_Sys_Finalize(pSysContext);
    free(pSysContext);
    pSysContext = NULL;
    return;
}

static void DoMyTestsWithSysContext(TSS2_SYS_CONTEXT *pSysContext)
{
    RunDefaultTestCase(pSysContext);
}

static void RunDefaultTestCase(TSS2_SYS_CONTEXT *pSysContext)
{
    UINT8 memoryToHash[] =
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa,
        0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9,
        0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7,
        0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6,
        0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5,
        0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff,
        0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4,
        0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe,
        0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3,
        0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd,
        0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2,
        0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc,
        0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1,
        0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb,
        0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa,
        0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9,
        0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7,
        0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6,
        0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5,
        0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff,
        0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4,
        0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe,
        0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3,
        0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd,
        0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2,
        0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc,
        0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1,
        0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb,
        0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa,
        0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9,
        0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
        0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7,
        0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6,
        0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5,
        0xf4, 0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff,
        0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4,
        0xf3, 0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe,
        0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3,
        0xf2, 0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd,
        0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2,
        0xf1, 0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc,
        0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1,
        0xf0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xfe, 0xfd, 0xfc, 0xfb,
        0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
        0xde, 0xad, 0xbe, 0xef,
    };

    TPM2B_DIGEST resultDigest;
    resultDigest.t.size = 0;  // 清除内存中的无效数据
    TPM2B_MAX_BUFFER package;
    size_t n;
    const uint8_t *p;

    try
    {
        HashSequenceScheduler scheduler(pSysContext);
        scheduler.start(TPM_ALG_SHA1, NULL);

        p = memoryToHash;
        n = sizeof(memoryToHash);
        while (n > MAX_DIGEST_BUFFER)  // 待处理的字节数 n 超过缓冲区最大容量时, 分多轮处理
        {
            package.t.size = MAX_DIGEST_BUFFER;
            memcpy(package.t.buffer, p, MAX_DIGEST_BUFFER);
            scheduler.update(&package);
            n -= MAX_DIGEST_BUFFER;  // 待处理的字节数 n 每轮递减若干字节
            p += MAX_DIGEST_BUFFER;  // 指针偏移量每轮向后递增若干字节
        }
        // 最后一轮处理
        memcpy(package.t.buffer, p, n);
        package.t.size = n;
        scheduler.update(&package);
        // 取回哈希摘要结果
        memset(&resultDigest, 0x00, sizeof(TPM2B_DIGEST));
        resultDigest.t.size = sizeof(TPM2B_DIGEST) - 2;
        scheduler.complete(&resultDigest);
    } catch (const char *err)
    {
        fprintf(stderr, "%s", err);
    }

    printf("SHA1 result:\n");
    for (size_t i = 0; i < resultDigest.t.size; i++)
    {
        printf("0x%02X, ", resultDigest.t.buffer[i]);
    }
    printf("\n");

    UINT8 goodHashValue[20] =
    {
        0xB3, 0xFD, 0x6A, 0xD2, 0x9F,
        0xD0, 0x13, 0x52, 0xBA, 0xFC,
        0x8B, 0x22, 0xC9, 0x6D, 0x88,
        0x42, 0xA3, 0x3C, 0xB0, 0xC9,
    };
    printf("Expected result:\n");
    for (size_t i = 0; i < sizeof(goodHashValue); i++)
    {
        printf("0x%02X, ", goodHashValue[i]);
    }
    printf("\n");
    if (memcmp(goodHashValue, resultDigest.t.buffer, sizeof(goodHashValue))
            == 0)
    {
        printf("SHA1 result is correct. Congratulations!\n");
    }
    else
    {
        printf("SHA1 result is wrong!!!\n");
    }
    return;
}

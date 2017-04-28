/* encoding: utf-8 */  // 使用 UTF-8 汉字编码
#ifndef __cplusplus // 调用 C stdio.h 等标准库
# include <stdio.h>
# include <stdlib.h>
# include <ctype.h>
#else
# include <cstdio>
# include <cstdlib>
# include <cctype>
using namespace std;
#endif

#include <sapi/tpm20.h>

#include "debug.h"
#include "tcti_util.h"

/* 自定义函数 */
static void DoMyTestsWithTctiContext(TSS2_TCTI_CONTEXT *pTctiContext);

/* 以下函数均使用4个空格缩进，不使用Tab缩进 */

static void PrintHelp()
{
    const char *version = "0.01";

    printf("My TPM client test app, Version %s\n", version);
    printf("用法:\n");
    printf("tpmclient [-rmhost hostname|IP address] [-rmport port]\n\n");
    printf("其中:\n");
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

inline TSS2_SYS_CONTEXT *pSysContextFromPVoid(void *pVoid)
{
#ifdef __cplusplus
    return static_cast<TSS2_SYS_CONTEXT*>(pVoid);
#else
    return (pVoid);
#endif
}

class NVSpaceTest
{
public:
    NVSpaceTest();
    void defineNVSpaceWithPassword(TPMI_RH_NV_INDEX nvIndex,
            const char *password);
    void undefineNVSpace(TPMI_RH_NV_INDEX nvIndex);
public:
    TSS2_SYS_CONTEXT *pSysContext;
};

static void DoMyTestsWithTctiContext(TSS2_TCTI_CONTEXT *pTctiContext)
{
    TSS2_RC rval;
    TSS2_ABI_VERSION abiVersion;
    TSS2_SYS_CONTEXT *pSysContext;
    size_t contextSize;

    contextSize = Tss2_Sys_GetContextSize(0);
    pSysContext = pSysContextFromPVoid(malloc(contextSize));
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

    /*
     * Test1:
     */
    class NVSpaceTest test1;
    test1.pSysContext = pSysContext;
    const TPMI_RH_NV_INDEX NV_INDEX = 0x01500020;
    const char password[] = "My hard-coded password";
    TPM2B_MAX_NV_BUFFER nvWriteData;
    nvWriteData.t.size = 2;
    for (int i = 0; i < nvWriteData.t.size; i++)
    {
        nvWriteData.t.buffer[i] = i + 1;
    }

    test1.defineNVSpaceWithPassword(NV_INDEX, password);  // 定义一块 NV 区域用于测试
    test1.undefineNVSpace(NV_INDEX);  // 测试结束时清除之前定义的 NV 区域

    /*
     * TODO: Add more tests here
     */

    /* Clean up the context when all tests ends */
    Tss2_Sys_Finalize(pSysContext);
    free(pSysContext);
    pSysContext = NULL;
    return;
}

NVSpaceTest::NVSpaceTest()
{
    this->pSysContext = NULL;
}

#include <time.h>

void NVSpaceTest::defineNVSpaceWithPassword(TPMI_RH_NV_INDEX nvIndex,
        const char *password)
{
    if (!this->pSysContext)
    {
        return;
    }
    /* 设置如何定义 NV 空间的参数 */
    TPM2B_NV_PUBLIC publicInfo;

    publicInfo.t.size = sizeof(TPMI_RH_NV_INDEX) + sizeof(TPMI_ALG_HASH)
            + sizeof(TPMA_NV) + sizeof(UINT16) + sizeof(UINT16);
    publicInfo.t.nvPublic.nvIndex = nvIndex;
    publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA1;
    publicInfo.t.nvPublic.dataSize = 32;
    memset(&(publicInfo.t.nvPublic.attributes), 0x00,
            sizeof(publicInfo.t.nvPublic.attributes));
    publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;  // 定义读NV数据时是否需要授权
    publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = 1;  // 定义写NV数据时是否需要授权
    publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
    publicInfo.t.nvPublic.authPolicy.t.size = 0;

    /* 创建以下结构体作为 Tss2_Sys_NV_DefineSpace() 的输入参数 TSS2_SYS_CMD_AUTHS */
    TPMS_AUTH_COMMAND cmdAuthNVDefine;
    TPMS_AUTH_COMMAND *commands[1];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;

    cmdAuthNVDefine.sessionHandle = TPM_RS_PW;
    memset(&(cmdAuthNVDefine.sessionAttributes), 0x00,
            sizeof(cmdAuthNVDefine.sessionAttributes));
    cmdAuthNVDefine.nonce.t.size = 0;
    cmdAuthNVDefine.hmac.t.size = 0;
    commands[0] = &cmdAuthNVDefine;
    cmdAuthsArray.cmdAuthsCount = 1;
    cmdAuthsArray.cmdAuths = &(commands[0]);

    /* 创建以下结构体作为 Tss2_Sys_NV_DefineSpace() 的输出参数 TSS2_SYS_RSP_AUTHS  */
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_RESPONSE *sessionDataOutArray[1];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;

    memset(&(sessionDataOut), 0x00, sizeof(sessionDataOut));
    sessionDataOutArray[0] = &sessionDataOut;
    rspAuthsArray.rspAuthsCount = 1;
    rspAuthsArray.rspAuths = &(sessionDataOutArray[0]);

    /* 指定密码 */
    TPM2B_AUTH nvAuth;  // nvAuth.t.buffer[] 在这里用于保存 password 明文

    nvAuth.t.size = strlen(password);
    memcpy(nvAuth.t.buffer, password, nvAuth.t.size);

    /* System API 函数调用 */
    TPM_RC rval = Tss2_Sys_NV_DefineSpace(pSysContext, TPM_RH_PLATFORM,
            &cmdAuthsArray, &nvAuth, &publicInfo, &rspAuthsArray);
    if (rval)
    {
        DebugPrintf(NO_PREFIX,
                "Tss2_Sys_NV_DefineSpace FAILED!  Ret code 0x%04X\n", rval);
        // FIXME: Tss2_Sys_NV_DefineSpace FAILED!  Ret code 0x01D5
    }

    /* 退出之前擦除内存中的密码副本 */
    srand(time(NULL));
    for (int i = 0; i < nvAuth.t.size; i++)
    {
        nvAuth.t.buffer[i] = (0xFF & rand());
    }
    nvAuth.t.size = 0;
}

void NVSpaceTest::undefineNVSpace(TPMI_RH_NV_INDEX nvIndex)
{
    if (!this->pSysContext)
    {
        return;
    }
    /* 创建以下结构体作为 Tss2_Sys_NV_UndefineSpace() 的输入参数 TSS2_SYS_CMD_AUTHS */
    TPMS_AUTH_COMMAND cmdAuthNVDefine;
    TPMS_AUTH_COMMAND *commands[1];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;

    cmdAuthNVDefine.sessionHandle = TPM_RS_PW;
    memset(&(cmdAuthNVDefine.sessionAttributes), 0x00,
            sizeof(cmdAuthNVDefine.sessionAttributes));
    cmdAuthNVDefine.nonce.t.size = 0;
    cmdAuthNVDefine.hmac.t.size = 0;
    commands[0] = &cmdAuthNVDefine;
    cmdAuthsArray.cmdAuthsCount = 1;
    cmdAuthsArray.cmdAuths = &(commands[0]);

    TPM_RC rval = Tss2_Sys_NV_UndefineSpace(pSysContext, TPM_RH_PLATFORM,
            nvIndex, &cmdAuthsArray, NULL);
    if (rval)
    {
        DebugPrintf(NO_PREFIX,
                "Tss2_Sys_NV_UndefineSpace FAILED!  Ret code 0x%04X\n", rval);
        // FIXME: Tss2_Sys_NV_UndefineSpace FAILED!  Ret code 0x028B
    }
}

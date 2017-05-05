/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <cstdio>
#include <cstdlib>
using namespace std;

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>

#include "KeyUtilities.h"

/* 自定义函数 */
static void DoMyTestsWithTctiContext(TSS2_TCTI_CONTEXT *pTctiContext);
static void DoMyTestsWithSysContext(TSS2_SYS_CONTEXT *pSysContext);
static void TestChildNodeCreation(TSS2_SYS_CONTEXT *pSysContext, TPM_HANDLE parent, const BYTE parentPassword[], size_t parentPasswordSize, const BYTE newChildPassword[], size_t newChildPasswordSize);

extern "C"
{

int DebugPrintf(printf_type type, const char *format, ...);
int DebugPrintfCallback(void *data, printf_type type, const char *format, ...);

void DebugPrintBuffer(printf_type type, UINT8 *command_buffer, UINT32 cnt1);
int DebugPrintBufferCallback(void *data, printf_type type, UINT8 *buffer,
        UINT32 length);

TSS2_RC InitSocketTctiContext(const TCTI_SOCKET_CONF *conf,
        TSS2_TCTI_CONTEXT **ppTctiContext);
void TeardownTctiContext(TSS2_TCTI_CONTEXT **ppTctiContext);

} /* End of extern "C" */

/* 排版格式: 以下函数均使用4个空格缩进，不使用Tab缩进 */

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
    TSS2_SYS_CONTEXT *sysContext = pSysContext;

    const TPMI_RH_HIERARCHY hierarchy = TPM_RH_NULL;
    if (TPM_RH_NULL == hierarchy)
    {
        printf("We will create a new key in TPM NULL-hierarchy.\n");
    }

    //printf("命令帧报文的 Authorization Area 字段, sessionHandle=TPM_RS_PW=%08H\n", TPM_RS_PW);
    TPMS_AUTH_COMMAND sessionData;
    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    memset(&(sessionData.sessionAttributes), 0x00, sizeof(TPMA_SESSION));
    TPMS_AUTH_COMMAND *cmdAuths[1];
    cmdAuths[0] = &sessionData;
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;
    cmdAuthsArray.cmdAuths = cmdAuths;
    cmdAuthsArray.cmdAuthsCount = 1;

    //printf("设置密钥初始条件(含有密码等敏感数据): \n");
    TPM2B_SENSITIVE_CREATE inSensitive;
    inSensitive.t.size = 0;
    inSensitive.t.sensitive.userAuth.t.size = strlen("abcd");
    inSensitive.t.sensitive.userAuth.t.buffer[0] = 'a';
    inSensitive.t.sensitive.userAuth.t.buffer[1] = 'b';
    inSensitive.t.sensitive.userAuth.t.buffer[2] = 'c';
    inSensitive.t.sensitive.userAuth.t.buffer[3] = 'd';
    if (inSensitive.t.sensitive.userAuth.t.size > 0)
    {
        inSensitive.t.size += sizeof(UINT16) + inSensitive.t.sensitive.userAuth.t.size;
    }
    inSensitive.t.sensitive.data.t.size = 0;
    if (inSensitive.t.sensitive.data.t.size > 0)
    {
        inSensitive.t.size += sizeof(UINT16) + inSensitive.t.sensitive.data.t.size;
    }

    //printf("选择密钥类型和算法: \n");
    TPM2B_PUBLIC inPublic;
    inPublic.t.publicArea.type = TPM_ALG_RSA;
    if (TPM_ALG_RSA == inPublic.t.publicArea.type)
    {
        printf("Key type: RSA.\n");
    }
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;
    memset(&(inPublic.t.publicArea.objectAttributes), 0x00, sizeof(UINT32));
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    inPublic.t.publicArea.authPolicy.t.size = 0;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    printf("Key size: %d bits.\n", inPublic.t.publicArea.parameters.rsaDetail.keyBits);
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.t.publicArea.unique.rsa.t.size = 0;

    //printf("其他输入参数\n");
    TPM2B_DATA outsideInfo;
    outsideInfo.t.size = 0;
    TPML_PCR_SELECTION creationPCR;
    creationPCR.count = 0;

    //printf("分别为各个输出参数预分配空间其他输入参数\n");
    TPM_HANDLE handle2048rsa;
    TPM2B_PUBLIC outPublic;
    outPublic.t.size = 0;
    TPM2B_CREATION_DATA creationData;
    creationData.t.size = 0;
    TPM2B_DIGEST creationHash;
    creationHash.t.size = sizeof(creationHash) - sizeof(UINT16);
    TPM2B_NAME keyName;
    keyName.t.size = sizeof(keyName) - sizeof(UINT16);
    TPMT_TK_CREATION creationTicket;
    creationTicket.tag = 0;
    creationTicket.hierarchy = 0x0;
    creationTicket.digest.t.size = sizeof(creationTicket.digest.t.buffer);

    //printf("应答帧报文的 Authorization Area\n");
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_RESPONSE *rspAuths[1];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;
    rspAuths[0] = &sessionDataOut;
    rspAuthsArray.rspAuths = rspAuths;
    rspAuthsArray.rspAuthsCount = 1;

    /* 发送 TPM 命令 */
    TPM_RC rc = Tss2_Sys_CreatePrimary(sysContext,
            hierarchy, //
            &cmdAuthsArray, //
            &inSensitive, //
            &inPublic, //
            &outsideInfo, //
            &creationPCR, //
            // 以上为输入参数
            // 以下为输出参数
            &handle2048rsa, //
            &outPublic, //
            &creationData, //
            &creationHash, //
            &creationTicket, //
            &keyName, //
            &rspAuthsArray //
            );
    if (rc)
    {
        fprintf(stderr, "ERROR: rc=0x%X\n", rc);
        if (TSS2_SYS_RC_BAD_VALUE == rc)
        {
            fprintf(stderr, "ERROR: TSS2_SYS_RC_BAD_VALUE=0x%X\n", TSS2_SYS_RC_BAD_VALUE);
        }
        //fprintf(stderr, "%s\n", GetErrMsgOfTPMResponseCode(rc));
        return;
    }
    printf("New key successfully created in NULL hierarchy (RSA 2048).  Handle: 0x%8.8x\n", handle2048rsa);
    printf("keyName.t.size=%d\n", keyName.t.size);
    printf("keyName data: ");
    for (size_t i=0; i<keyName.t.size; i++)
    {
        printf("0x%02X,", keyName.t.name[i]);
    }
    printf("\n");
    int printfNameOfHandle = 1;
    if (printfNameOfHandle)
    {
        const TPM_HANDLE KeyHandle = handle2048rsa;
        KeyPublicDataReadingOperation operation;
        operation.setKeyHandle(KeyHandle);
        try
        {
            operation.execute(pSysContext);
        }
        catch (TSS2_RC err)
        {
            fprintf(stderr, "KeyPublicDataReadingOperation::execute() Error=0x%X\n", err);
            if (TSS2_SYS_RC_BAD_VALUE == err)
            {
                fprintf(stderr, "ERROR: TSS2_SYS_RC_BAD_VALUE=0x%X\n", TSS2_SYS_RC_BAD_VALUE);
            }
            return;
        }
        const TPM2B_NAME& name = operation.getKeyName();
        printf("name.t.size=%d\n", name.t.size);
        printf("Key name data: ");
        for (size_t i=0; i<name.t.size; i++)
        {
            printf("0x%02X,", name.t.name[i]);
        }
        printf("\n");
    }

    char childPassword[] = "child password";
    TestChildNodeCreation(
            pSysContext,

            // 指定父节点句柄和节点授权访问密码
            handle2048rsa,
            inSensitive.t.sensitive.userAuth.t.buffer,
            inSensitive.t.sensitive.userAuth.t.size,

            // 另外提供新建子节点的访问密码
            (BYTE *)childPassword,
            strlen((char *)childPassword)
            );
}

static void TestChildNodeCreation(TSS2_SYS_CONTEXT *pSysContext, TPM_HANDLE parent, const BYTE parentPassword[], size_t parentPasswordSize, const BYTE newChildPassword[], size_t newChildPasswordSize)
{
    // ---------------------------------------------------------------------------------
    printf("Next, we will create a child key node under parent(0x%08X).\n",
            parent);
    HMACKeyCreationOperation keyCreator;

    keyCreator.setParentHandleWithAuthPassword(
            parent, // 指定父节点句柄和节点访问密码
            parentPassword,
            parentPasswordSize);
    keyCreator.setKeyNameHashAlgorithm(TPM_ALG_SHA1); // 密钥树节点名称哈希方法: TPM_ALG_SHA1/256/384/512 或 TPM_ALG_SM3_256

    printf("选择HMAC密钥所使用的哈希算法, 可从 TPM_ALG_SHA1/256/384/512 或 TPM_ALG_SM3_256 中任选其一\n");
    keyCreator.setHashAlgorithm(TPM_ALG_SHA1);

    printf("设置密钥的敏感数据(即指定子节点本身的访问密码). 仅用于后续功能测试\n");
    const BYTE NO_EXTRA_DATA[] = {'\0'};
    keyCreator.setSensitiveParameters(newChildPassword, newChildPasswordSize, NO_EXTRA_DATA, 0);

    // 尝试创建密钥, 检查错误返回码
    try
    {
        keyCreator.createKey(pSysContext);
    }
    catch (TSS2_RC err)
    {
        fprintf(stderr, "ERROR: HMACKeyCreationUtility::.createKey() Error=0x%X\n", err);
        if (TPM_RC_LOCKOUT == err)
        {
            fprintf(stderr, "TPM_RC_LOCKOUT=0x%X\n", TPM_RC_LOCKOUT);
            fprintf(stderr, "TPM has been lockout at this moment. Check or reset TPM Dictionary-Attack-Lock settings, please.\n");
        }
        return;
    }
    printf("Child key node has been created successfully.\n");

    // ---------------------------------------------------------------------------------
    printf("Next, 让 TPM 加载密钥节点.\n");
    KeyLoadingOperation keyLoader;

    keyLoader.setParentHandleWithAuthPassword(
            parent, // 指定父节点句柄和节点访问密码
            parentPassword,
            parentPasswordSize
            );
    try
    {
        keyLoader.loadExistingKey(
                pSysContext, // 上下文指针
                keyCreator.outPrivate, // 引用
                keyCreator.outPublic //
                );
        printf("TPM 加载成功, 新节点的句柄=0x%X\n", keyLoader.keyHandle);
        printf("Load 命令取回的结果是: keyLoader.keyName.t.size=%d\n", keyLoader.keyName.t.size);
        printf("十六进制数据:");
        for (size_t i=0; i<keyLoader.keyName.t.size; i++)
        {
            printf(" 0x%02X,", keyLoader.keyName.t.name[i]);
        }
        printf("\n");
    }
    catch (TSS2_RC err)
    {
        fprintf(stderr, "ERROR: err=0x%X\n", err);
        if (TSS2_SYS_RC_BAD_VALUE == err)
        {
            fprintf(stderr, "ERROR: TSS2_SYS_RC_BAD_VALUE=0x%X\n", TSS2_SYS_RC_BAD_VALUE);
        }
        if (TSS2_SYS_RC_INSUFFICIENT_BUFFER == err)
        {
            fprintf(stderr, "ERROR: TSS2_SYS_RC_INSUFFICIENT_BUFFER=0x%X\n", TSS2_SYS_RC_INSUFFICIENT_BUFFER);
            //fprintf(stderr, "TPM2B_NAME::t.size = %d, 可能size没有初始化\n", loadingUtil.keyName.t.size);
        }
        if (TPM_RC_LOCKOUT == err)
        {
            fprintf(stderr, "TPM_RC_LOCKOUT=0x%X\n", TPM_RC_LOCKOUT);
            fprintf(stderr, "TPM has been lockout at this moment. Check or reset TPM Dictionary-Attack-Lock settings, please.\n");
        }
        return;
    }

    // ---------------------------------------------------------------------------------
    printf("Next, 调用 ReadPublic 命令查看该密钥节点的节点名.\n");
    KeyPublicDataReadingOperation readpublic;

    readpublic.setKeyHandle(keyLoader.keyHandle);
    try
    {
        readpublic.execute(pSysContext);
        printf("ReadPublic 命令取回的结果是: reader.keyName.t.size=%d\n", readpublic.keyName.t.size);
        printf("十六进制数据:");
        for (size_t i=0; i<readpublic.keyName.t.size; i++)
        {
            printf(" 0x%02X,", readpublic.keyName.t.name[i]);
        }
        printf("\n");
        printf("备注: 对比 Load、ReadPublic 两条命令各自取回的结果(应该一致)\n");
    }
    catch (TSS2_RC err)
    {
        fprintf(stderr, "ERROR: err=0x%X\n", err);
        return;
    }
}

/* 调试专用函数 */
#include <stdarg.h>

extern "C"
{

int DebugPrintf(printf_type type, const char *format, ...)
{
    va_list args;
    int rval = 0;

    if (type == RM_PREFIX)
    {
        printf("||  ");
    }
    va_start(args, format);
    rval = vprintf(format, args);
    va_end(args);

    return rval;
}

int DebugPrintfCallback(void *data, printf_type type, const char *format, ...)
{
    va_list args;
    int rval = 0;

    if (type == RM_PREFIX)
    {
        DebugPrintfCallback(data, NO_PREFIX, "||  ");
    }
    va_start(args, format);
    rval = vprintf(format, args);
    va_end(args);

    return rval;
}

void DebugPrintBuffer(printf_type type, UINT8 *buffer, UINT32 length)
{
    UINT32 i;

    for (i = 0; i < length; i++)
    {
        if ((i % 16) == 0)
        {
            DebugPrintf(NO_PREFIX, "\n");
            if (type == RM_PREFIX)
            {
                DebugPrintf(NO_PREFIX, "||  ");
            }
        }

        DebugPrintf(NO_PREFIX, "%2.2x ", buffer[i]);
    }
    DebugPrintf(NO_PREFIX, "\n\n");
    fflush (stdout);
}

int DebugPrintBufferCallback(void *data, printf_type type, UINT8 *buffer,
        UINT32 length)
{
    DebugPrintBuffer(type, buffer, length);
    return 0;
}

} /* End of extern "C" */
/* End of 调试专用函数 */

/* 自定义: 对TCTI底层接口进行的封装 */
extern "C"
{

static size_t GetSocketTctiContextSize()
{
    TCTI_SOCKET_CONF emptyConf;
    const uint8_t noSeverSockets = 0;
    size_t size;
    TSS2_RC err;

    err = InitSocketTcti(NULL, &size, &emptyConf, noSeverSockets);
    if (err)
    {
        fprintf(stderr,
                "Error: Failed to fetch size of TSS2_TCTI_CONTEXT from libtcti-socket\n");
        fprintf(stderr, "(This error should NEVER happen)\n");
        exit(0);
    }
    return size;
}

TSS2_RC InitSocketTctiContext(const TCTI_SOCKET_CONF *conf,
        TSS2_TCTI_CONTEXT **tcti_context)
{
    size_t size;

    size = GetSocketTctiContextSize();
    *tcti_context = (TSS2_TCTI_CONTEXT *) malloc(size);
    return InitSocketTcti(*tcti_context, &size, conf, 0);
}

void TeardownTctiContext(TSS2_TCTI_CONTEXT **tctiContext)
{
    if (*tctiContext != NULL)
    {
        tss2_tcti_finalize(*tctiContext);
        free(*tctiContext);
        *tctiContext = NULL;
    }
}

} /* End of extern "C" */
/* End of 自定义: 对TCTI底层接口进行的封装 */

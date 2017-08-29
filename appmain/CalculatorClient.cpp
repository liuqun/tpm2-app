/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <vector>
using std::vector;
#include <sstream>
using std::ostringstream;
#include <stdexcept>
using std::runtime_error;
#include "CalculatorClient.h"
#include "TPMCommand.h"

/// ```
/// TPM2B_MAX_BUFFER *p=NULL;
/// const static unsigned short MaxBlockSize = sizeof(p->t.buffer);
/// ```
static const unsigned short MaxBlockSize=1024; ///< 单个数据包最大可发送的字节数

// 采取对象包装器模式, 完成TSS上下文初始化
void HashCalculatorClient::initialize(TSSContextInitializer & initializer)
{
    m_scheduler.initialize(initializer);
}

// 采取对象包装器模式, 间接转发TPM命令帧
void HashCalculatorClient::sendCommand(TPMCommand& command)
{
    m_scheduler.sendCommand(command);
}

// 采取对象包装器模式, 间接取回TPM应答帧
void HashCalculatorClient::fetchResponse(int32_t timeout)
{
    m_scheduler.fetchResponse(timeout);
}

// 计算SHA256哈希摘要结果
const vector<unsigned char>& HashCalculatorClient::SHA256(const void *data, // 指向输入数据的指针
        unsigned long long length // 数据长度. 单位: 字节. 取值范围[0, ULLONG_MAX]
        ) {
    if (length > MaxBlockSize) {
        m_digest.clear();
        try {
            unsigned long long left = length;
            const unsigned char *p = (const unsigned char *) data;

            m_scheduler.start(TPM_ALG_SHA256);
            while (left)
            {
                unsigned short n = MaxBlockSize;
                if (left < MaxBlockSize)
                {
                    n = (unsigned short) left;
                }
                m_scheduler.inputData(p, n);
                p += n;
                left -= n;
            }
            m_scheduler.complete();

            const TPM2B_DIGEST& digest = m_scheduler.outDigest();
            m_digest.assign(digest.t.buffer, digest.t.buffer + digest.t.size);
        } catch (std::exception& err) {
            std::ostringstream msg;
            msg << "Error: 命令执行失败! " << err.what();
            throw std::runtime_error(msg.str());
        } catch (...) {
            std::ostringstream msg;
            msg << "An unknown error was detected from " << __FILE__ << ":" << __LINE__ << ":" << __FUNCTION__;
            throw std::runtime_error(msg.str());
        }
        return m_digest;
    }

    TPMCommands::Hash hashCmd;
    hashCmd.configHashAlgorithmUsingSHA256();
    m_digest.clear();
    try {
        hashCmd.configInputData(data, length);
        sendCommand(hashCmd);
        fetchResponse();
        const TPM2B_DIGEST &outHash = hashCmd.outHash();
        m_digest.assign(outHash.t.buffer, outHash.t.buffer+outHash.t.size);
    } catch (...) {
        std::ostringstream msg;
        msg << "An unknown error was detected from " << __FILE__ << ":" << __LINE__ << ":" << __FUNCTION__;
        throw std::runtime_error(msg.str());
    }
    return m_digest;
}

// 计算SHA1哈希摘要结果
const vector<unsigned char>& HashCalculatorClient::SHA1(const void *data, // 指向输入数据的指针
        unsigned long long length // 数据长度. 单位: 字节. 取值范围[0, ULLONG_MAX]
        ) {
    if (length > MaxBlockSize) {
        m_digest.clear();
        try {
            unsigned long long left = length;
            const unsigned char *p = (const unsigned char *) data;

            m_scheduler.start(TPM_ALG_SHA1);
            while (left)
            {
                unsigned short n = MaxBlockSize;
                if (left < MaxBlockSize)
                {
                    n = (unsigned short) left;
                }
                m_scheduler.inputData(p, n);
                p += n;
                left -= n;
            }
            m_scheduler.complete();

            const TPM2B_DIGEST& digest = m_scheduler.outDigest();
            m_digest.assign(digest.t.buffer, digest.t.buffer + digest.t.size);
        } catch (std::exception& err) {
            std::ostringstream msg;
            msg << "Error: 命令执行失败! " << err.what();
            throw std::runtime_error(msg.str());
        } catch (...) {
            std::ostringstream msg;
            msg << "An unknown error was detected from " << __FILE__ << ":" << __LINE__ << ":" << __FUNCTION__;
            throw std::runtime_error(msg.str());
        }
        return m_digest;
    }

    TPMCommands::Hash hashCmd;
    hashCmd.configHashAlgorithmUsingSHA1();
    m_digest.clear();
    try {
        hashCmd.configInputData(data, length);
        sendCommand(hashCmd);
        fetchResponse();
        const TPM2B_DIGEST &outHash = hashCmd.outHash();
        m_digest.assign(outHash.t.buffer, outHash.t.buffer+outHash.t.size);
    } catch (...) {
        std::ostringstream msg;
        msg << "An unknown error was detected from " << __FILE__ << ":" << __LINE__ << ":" << __FUNCTION__;
        throw std::runtime_error(msg.str());
    }
    return m_digest;
}

/// 是否开启printf调试信息
#define ENABLE_DEBUG_PRINTF 1 ///< 可选值: 0表示禁用printf(); 1或任意非零值表示允许输出printf()调试信息.

#if ENABLE_DEBUG_PRINTF
#include <cstdio>
#warning // printf() has been enabled now. (To disable printf, you may set ENABLE_DEBUG_PRINTF to 0)
#endif

#if !ENABLE_DEBUG_PRINTF
inline static int NoPrintf()
{
    return (0);
}
// 通过函数名宏替换的方式注释掉所有printf语句
#undef printf
#define printf(...) NoPrintf()
#undef fprintf
#define fprintf(fp, ...) NoPrintf()
#endif

#include "TPMCommand.h"
using TPMCommands::HMAC;
using TPMCommands::LoadExternal;
using TPMCommands::FlushLoadedKeyNode;

// 内部函数 RunHMACCalcProgram()
// 执行HMAC对称签名程序
static void RunHMACCalcProgram(
        HMACCalculatorClient& client, // 通过client发送命令帧
        TPMI_ALG_HASH hashAlg, // 指定哈希算法
        vector<unsigned char>& outResult, // 输出HMAC结果
        const void *data, // 指向输入数据的指针
        unsigned short nDatalength, // 数据长度. 单位: 字节. 取值范围[0, 1024], 单条输入数据的长度上限受TSS和物理硬件共同限制, 实际上限有可能小于1024字节
        const void *key, // HMAC签名密钥值
        unsigned short nKeyLength // 密钥长度
        ) {
    outResult.clear();

    TPMI_RH_HIERARCHY hierarchy = TPM_RH_NULL; // 在 TPM_RH_NULL 区域创建的节点是临时节点
    const char *ExternalKeyPassword = "";
    const UINT16 ExternalKeyPasswordLen = strlen(ExternalKeyPassword);
    try {
        TPMCommands::LoadExternal loadextn;
        printf("设置 LoadExternal 命令帧参数\n");
        loadextn.configHierarchy(hierarchy);
        loadextn.configSensitiveDataBits(key, nKeyLength);
        loadextn.configHMACKeyUsingHashAlgorithm(hashAlg);
        loadextn.configKeyAuthValue(ExternalKeyPassword, ExternalKeyPasswordLen);
        printf("发送 LoadExternal 命令桢创建临时节点(用于存储用户输入的自定义对称密钥)\n");
        client.sendCommand(loadextn);
        client.fetchResponse();
        {
            char buf[nKeyLength];
            memset(buf, 0xFF, nKeyLength);
            loadextn.configSensitiveDataBits(buf, nKeyLength); // 手动覆盖清除之前缓存的对称密钥值副本(属于敏感数据)
        }
        printf("临时节点创建成功, 密钥句柄=0x%08X\n", (int)loadextn.outObjectHandle());

        printf("调用单条 HMAC 命令\n");
        TPMCommands::HMAC hmac;
        try {
            printf("设置 HMAC 命令帧的参数\n");
            TPM_HANDLE keyHandle = loadextn.outObjectHandle();
            hmac.configHMACKey(keyHandle);
            hmac.configAuthSession(TPM_RS_PW);
            hmac.configAuthPassword(ExternalKeyPassword, ExternalKeyPasswordLen);
            hmac.configInputData(data, nDatalength);
            hmac.configUsingHashAlgorithm(hashAlg);

            printf("发送 HMAC 命令桢\n");
            client.sendCommand(hmac);
            client.fetchResponse();

            printf("解析 HMAC 应答桢\n");
            const TPM2B_DIGEST& result = hmac.outHMAC();
            outResult.assign(result.t.buffer, result.t.buffer+result.t.size);
        } catch (TSS2_RC rc) {
            std::ostringstream msg;
            msg << "TPM Command HMAC() has returned an error code 0x" << std::hex << rc;
            throw std::runtime_error(msg.str());
        } catch (...) {
            throw std::runtime_error("Unknown error happened in TPM command HMAC()\n");
        }

        printf("调用 Flush 命令清理临时节点\n");
        TPMCommands::FlushLoadedKeyNode flush;
        TPM_HANDLE h = loadextn.outObjectHandle();
        if ((TPM_RH_NULL == hierarchy) && (h & 0xFF000000) != 0x80000000) {
            std::ostringstream msg;
            msg << "Unexpected TPM HANDLE h=0x" << std::hex << (int)h << ", under hierarchy=0x" << (int)hierarchy;
            throw std::runtime_error(msg.str());
        }
        flush.configKeyNodeToFlushAway(h);
        printf("发送 FlushContext 命令桢, 让 TPM 删除之前 LoadExternal 命令加载的节点\n");
        client.sendCommand(flush);
        client.fetchResponse();
        printf("节点删除完毕\n");
    } catch (TSS2_RC rc) {
        std::ostringstream msg;
        msg << "TPM Command LoadExternal() has returned an error code 0x" << std::hex << rc;
        throw std::runtime_error(msg.str());
    } catch (std::exception& e) {
        std::ostringstream msg;
        msg << "TPM Command FlushContext(): An error happened: " << e.what();
        throw std::runtime_error(msg.str());
    } catch (...) {
        throw std::runtime_error("Unknown error happened in TPM command LoadExternal() or FlushContext()");
    }
}

// 计算SHA1-HMAC
const vector<unsigned char>& HMACCalculatorClient::HMAC_SHA1(
        const void *data, // 指向输入数据的指针
        unsigned short nDatalength, // 数据长度. 单位: 字节. 取值范围[0, 1024], 单条输入数据的长度上限受TSS和物理硬件共同限制, 实际上限有可能小于1024字节
        const void *key, // HMAC签名密钥值
        unsigned short nKeyLength // 密钥长度
        ) {
    RunHMACCalcProgram(*this, TPM_ALG_SHA1, m_hmacDigest, data, nDatalength, key, nKeyLength);
    return m_hmacDigest;
}

// 计算SHA256-HMAC
const vector<unsigned char>& HMACCalculatorClient::HMAC_SHA256(
        const void *data, // 指向输入数据的指针
        unsigned short nDatalength, // 数据长度. 单位: 字节. 取值范围[0, 1024], 单条输入数据的长度上限受TSS和物理硬件共同限制, 实际上限有可能小于1024字节
        const void *key, // HMAC签名密钥值
        unsigned short nKeyLength // 密钥长度
        ) {
    RunHMACCalcProgram(*this, TPM_ALG_SHA256, m_hmacDigest, data, nDatalength, key, nKeyLength);
    return m_hmacDigest;
}

/* 以下代码实现 FileHashCalculatorClient 类 */

// 计算文件的SHA1
const std::vector<unsigned char>& FileHashCalculatorClient::SHA1(FILE *fpFileIn)
{
    m_digest.clear();
    try
    {
        BYTE buf[2*1024];
        const int nBufSize = sizeof(buf);
        int len = 0;

        m_scheduler.start(TPM_ALG_SHA1);
        while (!(feof(fpFileIn)))
        {
            len = fread(buf, sizeof(BYTE), nBufSize, fpFileIn);
            if (len > 0)
            {
                m_scheduler.inputData(buf, len);
            }
        }
        m_scheduler.complete();

        const TPM2B_DIGEST& digest = m_scheduler.outDigest();
        m_digest.assign(digest.t.buffer, digest.t.buffer + digest.t.size);
    }
    catch (std::exception& err)
    {
        fprintf(stderr, "Error: %s\n", err.what());
    }
    return m_digest;
}

// 计算文件的SHA256
const std::vector<unsigned char>& FileHashCalculatorClient::SHA256(FILE *fpFileIn)
{
    m_digest.clear();
    try
    {
        BYTE buf[2*1024];
        const int nBufSize = sizeof(buf);
        int len = 0;

        m_scheduler.start(TPM_ALG_SHA256);
        while (!(feof(fpFileIn)))
        {
            len = fread(buf, sizeof(BYTE), nBufSize, fpFileIn);
            if (len > 0)
            {
                m_scheduler.inputData(buf, len);
            }
        }
        m_scheduler.complete();

        const TPM2B_DIGEST& digest = m_scheduler.outDigest();
        m_digest.assign(digest.t.buffer, digest.t.buffer + digest.t.size);
    }
    catch (std::exception& err)
    {
        fprintf(stderr, "Error: %s\n", err.what()); // TODO: raise/throw another exception to the uppper level
    }
    return m_digest;
}

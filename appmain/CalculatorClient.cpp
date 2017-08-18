/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <vector>
using std::vector;
#include <sstream>
using std::stringstream;
#include <stdexcept>
using std::runtime_error;
#include "CalculatorClient.h"
#include "TPMCommand.h"

// 计算SHA256哈希摘要结果
const vector<unsigned char>& HashCalculatorClient::SHA256(const void *data, // 指向输入数据的指针
        unsigned short length // 数据长度. 单位: 字节. 取值范围[0, 1024], 单条输入数据的长度上限受TSS和物理硬件共同限制, 实际上限有可能小于1024字节
        ) {
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
        std::stringstream msg;
        msg << "An unknown error was detected from " << __FILE__ << ":" << __LINE__ << ":" << __FUNCTION__;
        throw std::runtime_error(msg.str());
    }
    return m_digest;
}

// 计算SHA1哈希摘要结果
const vector<unsigned char>& HashCalculatorClient::SHA1(const void *data, // 指向输入数据的指针
        unsigned short length // 数据长度. 单位: 字节. 取值范围[0, 1024], 单条输入数据的长度上限受TSS和物理硬件共同限制, 实际上限有可能小于1024字节
        ) {
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
        std::stringstream msg;
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
        TPMCommands::HMAC& hmac, // 已经预设好哈希算法选项的单条 HMAC 命令
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
        loadextn.configHMACKeyUsingHashAlgorithm();
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
        try {
            printf("设置 HMAC 命令帧的参数\n");
            TPM_HANDLE keyHandle = loadextn.outObjectHandle();
            hmac.configHMACKey(keyHandle);
            hmac.configAuthSession(TPM_RS_PW);
            hmac.configAuthPassword(ExternalKeyPassword, ExternalKeyPasswordLen);
            hmac.configInputData(data, nDatalength);

            printf("发送 HMAC 命令桢\n");
            client.sendCommand(hmac);
            client.fetchResponse();

            printf("解析 HMAC 应答桢\n");
            const TPM2B_DIGEST& result = hmac.outHMAC();
            outResult.assign(result.t.buffer, result.t.buffer+result.t.size);
        } catch (TSS2_RC rc) {
            std::stringstream msg;
            msg << "TPM Command HMAC() has returned an error code 0x" << std::hex << rc;
            throw std::runtime_error(msg.str());
        } catch (...) {
            throw std::runtime_error("Unknown error happened in TPM command HMAC()\n");
        }

        printf("调用 Flush 命令清理临时节点\n");
        TPMCommands::FlushLoadedKeyNode flush;
        TPM_HANDLE h = loadextn.outObjectHandle();
        if ((TPM_RH_NULL == hierarchy) && (h & 0xFF000000) != 0x80000000) {
            std::stringstream msg;
            msg << "Unexpected TPM HANDLE h=0x" << std::hex << (int)h << ", under hierarchy=0x" << (int)hierarchy;
            throw std::runtime_error(msg.str());
        }
        flush.configKeyNodeToFlushAway(h);
        printf("发送 FlushContext 命令桢, 让 TPM 删除之前 LoadExternal 命令加载的节点\n");
        client.sendCommand(flush);
        client.fetchResponse();
        printf("节点删除完毕\n");
    } catch (TSS2_RC rc) {
        std::stringstream msg;
        msg << "TPM Command LoadExternal() has returned an error code 0x" << std::hex << rc;
        throw std::runtime_error(msg.str());
    } catch (std::exception& e) {
        std::stringstream msg;
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
    TPMCommands::HMAC hmac;
    hmac.configUsingHashAlgorithmSHA1();
    RunHMACCalcProgram(*this, hmac, m_hmacDigest, data, nDatalength, key, nKeyLength);
    return m_hmacDigest;
}

// 计算SHA256-HMAC
const vector<unsigned char>& HMACCalculatorClient::HMAC_SHA256(
        const void *data, // 指向输入数据的指针
        unsigned short nDatalength, // 数据长度. 单位: 字节. 取值范围[0, 1024], 单条输入数据的长度上限受TSS和物理硬件共同限制, 实际上限有可能小于1024字节
        const void *key, // HMAC签名密钥值
        unsigned short nKeyLength // 密钥长度
        ) {
    TPMCommands::HMAC hmac;
    hmac.configUsingHashAlgorithmSHA256();
    RunHMACCalcProgram(*this, hmac, m_hmacDigest, data, nDatalength, key, nKeyLength);
    return m_hmacDigest;
}

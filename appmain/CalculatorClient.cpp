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

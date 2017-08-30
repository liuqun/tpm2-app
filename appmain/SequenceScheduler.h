/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef SEQUENCE_SCHEDULER_H_
#define SEQUENCE_SCHEDULER_H_

#ifndef __cplusplus
#warning // Only C++ is supported. Please DON'T include this file from *.c!
#endif

#include <sapi/tpm20.h>
#include "Client.h"

#ifdef __cplusplus

/// Hash sequence 调度器
class HashSequenceScheduler: public Client
{
public:
    HashSequenceScheduler();
    ~HashSequenceScheduler();

    /// 开启Hash计算序列
    ///
    /// @param hashAlgorithm TPM2.0 哈希算法编号. 遇到无效的哈希算法编号则尝试使用keyHandle密钥中的指定的哈希算法
    /// @throws std::exception 通过 std::exception::what() 描述错误原因
    void start(TPMI_ALG_HASH hashAlgorithm);

    /// 序列输入下一个数据包
    ///
    /// @param data
    /// @param length
    /// @throws std::exception 通过 std::exception::what() 描述错误原因
    void inputData(const void *data, unsigned int length);

    /// 结束当前Hash计算序列, 取回计算结果后存储在类成员变量中
    ///
    /// @throws std::exception 通过 std::exception::what() 描述错误原因
    void complete();

    /// 输出哈希摘要
    ///
    /// @return TPM2B_DIGEST 结构体引用
    const TPM2B_DIGEST& outDigest();

    /// 输出凭证
    ///
    /// @return TPMT_TK_HASHCHECK 结构体引用
    const TPMT_TK_HASHCHECK& outValidationTicket();

private:
    TPM2B_DIGEST m_hashDigest;///< 存储最终HMAC结果
private:
    TPMT_TK_HASHCHECK m_validationTicket;///< 存储本次计算是由TPM完成的校验凭证
private:
    TPM2B_MAX_BUFFER m_cachedData;///< 预留缓存区, 提高IO效率
private:
    TPMI_DH_OBJECT m_savedSequenceHandle;
private:
    TPM2B_AUTH m_savedAuthValueForSequenceHandle;
};

/// HMAC sequence 调度器
class HMACSequenceScheduler: public Client
{
public:
    HMACSequenceScheduler();
    ~HMACSequenceScheduler();

    /// 开启HMAC序列
    ///
    /// @param hashAlgorithm TPM2.0 哈希算法编号. 遇到无效的哈希算法编号则尝试使用keyHandle密钥中的指定的哈希算法
    /// @param key
    /// @param keyLength
    /// @param keyPassword
    /// @param keyPasswordLength
    /// @throws std::exception 通过 std::exception::what() 描述错误原因
    void start(TPMI_ALG_HASH hashAlgorithm, const void *key, unsigned int keyLength, const void *keyPassword="", unsigned int keyPasswordLength=0);

    /// HMAC序列输入下一个数据包
    ///
    /// @param data
    /// @param length
    /// @throws std::exception 通过 std::exception::what() 描述错误原因
    void inputData(const void *data, unsigned int length);

    /// 结束当前HMAC序列, 取回计算结果后存储在类成员变量中
    ///
    /// @throws std::exception 通过 std::exception::what() 描述错误原因
    void complete();

    /// 输出HMAC
    ///
    /// @return TPM2B_DIGEST 结构体引用
    const TPM2B_DIGEST& outHMAC();

    /// 输出凭证
    ///
    /// @return TPMT_TK_HASHCHECK 结构体引用
    const TPMT_TK_HASHCHECK& outValidationTicket();

private:
    TPM2B_DIGEST m_hmacDigest;///< 存储最终HMAC结果
private:
    TPMT_TK_HASHCHECK m_validationTicket;///< 存储本次计算是由TPM完成的校验凭证
private:
    TPM2B_MAX_BUFFER m_cachedData;///< 预留缓存区, 提高IO效率
private:
    TPMI_DH_OBJECT m_savedSequenceHandle;
private:
    TPM2B_AUTH m_savedAuthValueForSequenceHandle;
};

#endif // __cplusplus
#endif // SEQUENCE_SCHEDULER_H_

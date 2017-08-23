/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef CLIENT_H_
#define CLIENT_H_

#ifndef __cplusplus
#warning // Only C++ is supported. Please DON'T include this file from *.c!
#endif

#include <sapi/tpm20.h>
#include "TPMCommand.h"
#include "TSSContextInitializer.h"

#ifdef __cplusplus

/// TPM客户端
class Client
{
private:
    size_t m_sysContextSize;

public:
    TSS2_SYS_CONTEXT *m_sysContext; ///< 成员变量 m_sysContext (取代全局变量 sysContext, 降低耦合度).
    /** 构造函数 */
    Client();
    /** 客户端初始化 */
    void initialize(TSSContextInitializer& initializer);
    /** 析构函数 */
    virtual ~Client();
    /** 发送命令帧 */
    void sendCommand(
            TPMCommand& command ///< 输入参数. 此TPMCommand对象自带buildCmdPacket()组帧方法生成命令帧报文
            );
    /**
     * 取回应答帧
     *
     * @note 该函数放在每条sendCommand()之后被调用. 若没有发送过命令帧, 则无法取回的应答桢.
     * @note 若该函数执行成功, 返回的数据将被写入之前调用 sendCommand() 时指定的 command 对象.
     *
     * @throws TSS2_RC (可能遇到多种错误情况, 包括TSS层或TPM硬件返回的错误码) TODO: 此处需补充文档和样例代码帮助开发者处理不同的 TPM_RC/TSS2_RC 错误编码.
     */
    void fetchResponse(
            int32_t timeout=-1 ///< 超时选项. 默认使用负数表示阻塞等待, 直到服务器端应答或者发生其他严重错误
            );
    /** 发送命令帧并取回应答帧 */
    void sendCommandAndWaitUntilResponseIsFetched(
            TPMCommand& cmd ///< 输入参数. 此TPMCommand对象自带buildCmdPacket()组帧方法生成命令帧报文
            );

private:
    TPMCommand *m_pLastCommand; ///< 内部成员变量. m_pLastCommand总是指向之前最后一次调用sendCommand()成员函数时的关联的TPMCommand参数的内存地址
};

class SequenceScheduler: public Client
{
};

class HMACSequenceScheduler: public SequenceScheduler
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

class HashSequenceScheduler: public SequenceScheduler
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

#endif // __cplusplus
#endif // CLIENT_H_

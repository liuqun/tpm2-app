/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef CALCULATOR_CLIENT_H_
#define CALCULATOR_CLIENT_H_

#ifndef __cplusplus
#warning // Only C++ is supported. Please DON'T include this file from *.c!
#endif

#ifdef __cplusplus

#include <vector>
#include "Client.h"

/// 计算单个数据包的哈希摘要, 输入数据的最大长度由TPM硬件以及TSS动态库限制, 通常为1024字节
class HashCalculatorClient: public WrapperClient
{
public:
    /// 计算SHA256哈希摘要结果
    ///
    /// @return 哈希摘要结果, 格式为二进制数据, 类型为 const vector<BYTE>& C++ 指针引用
    /// @throws std::exception 代表执行失败, 可能导致执行失败的原因包括: TPM设备应答异常, TPM资源管理器错误以及其他未知错误
    const std::vector<unsigned char>& SHA256(const void *data, ///< 指向输入数据的指针
            unsigned long long length ///< 数据长度. 单位: 字节. 取值范围[0, ULLONG_MAX]. ULLONG_MAX 的值定义自 <limits.h>.
            );

public:
    /// 计算SHA1哈希摘要结果
    ///
    /// @return 哈希摘要结果, 格式为二进制数据, 类型为 const vector<BYTE>& C++ 指针引用
    /// @throws std::exception 代表执行失败, 可能导致执行失败的原因包括: TPM设备应答异常, TPM资源管理器错误以及其他未知错误
    const std::vector<unsigned char>& SHA1(const void *data, ///< 指向输入数据的指针
            unsigned long long length ///< 数据长度. 单位: 字节. 取值范围[0, ULLONG_MAX]. ULLONG_MAX 的值定义自 <limits.h>.
            );

protected:
    /// 哈希摘要结果(私有数据存储区)
    std::vector<unsigned char> m_digest;

public:
    /// 客户端初始化
    void initialize(TSSContextInitializer& initializer);

protected:
    /// 私有成员变量, 通过 TPM2.0 hash sequence 调度程序完成哈希计算
    HashSequenceScheduler m_scheduler;

public:
    /// 发送命令帧
    void sendCommand(TPMCommand& command ///< 输入参数. 此TPMCommand对象自带buildCmdPacket()组帧方法生成命令帧报文
            );

public:
    /// 取回应答帧
    ///
    /// 若该函数执行成功, 返回的数据将被写入之前调用 sendCommand() 时指定的 command 对象. 否则不会改变任何之前引用的数据结构体
    ///
    /// @throws TSS2_RC (可能遇到多种错误情况, 包括TSS层或TPM硬件返回的错误码) TODO: 此处需补充文档和样例代码帮助开发者处理不同的 TPM_RC/TSS2_RC 错误编码.
    /// @note 该函数放在每条sendCommand()之后被调用. 若没有发送过命令帧, 则无法取回的应答桢.
    void fetchResponse(int32_t timeout=-1 ///< 超时选项. 默认使用负数表示阻塞等待, 直到服务器端应答或者发生其他严重错误
            );
};


#include <cstdio>

/// 计算文件的哈希摘要
class FileHashCalculatorClient: public HashCalculatorClient
{
public:
    /// 计算SHA1哈希摘要结果
    ///
    /// @return SHA1 哈希摘要结果, 格式为二进制数据, 类型为 const vector<BYTE>& C++ 指针引用
    const std::vector<unsigned char>& SHA1(FILE *fpFileIn=stdin ///< 通过标准文件IO流读取输入数据
            );

    /// 计算SHA256哈希摘要结果
    ///
    /// @return SHA256 哈希摘要结果, 格式为二进制数据, 类型为 const vector<BYTE>& C++ 指针引用
    const std::vector<unsigned char>& SHA256(FILE *fpFileIn=stdin ///< 通过标准文件IO流读取输入数据
            );
};

/// 计算单个数据包的HMAC对称签名, 输入数据的最大长度由TPM硬件以及TSS动态库限制, 通常为1024字节
class HMACCalculatorClient: public Client
{
public:
    /// 计算HMAC称签名(HMAC-SHA1)
    ///
    /// @return 二进制数据, 类型为 const vector<BYTE>& C++ 指针引用
    /// @throws std::exception 代表执行失败, 可能导致执行失败的原因包括: TPM设备应答异常, TPM资源管理器错误以及其他未知错误
    const std::vector<unsigned char>& HMAC_SHA1(
            const void *data, ///< 指向输入数据的指针
            unsigned short nDatalength, ///< 数据长度. 单位: 字节. 取值范围[0, 1024], 单条输入数据的长度上限受TSS和物理硬件共同限制, 实际上限有可能小于1024字节
            const void *key, ///< HMAC签名密钥值
            unsigned short nKeyLength ///< HMAC签名密钥长度. 单位: 字节. 取值范围[1, 128]. @note MAX_SYM_DATA=128 字节, 由 "sapi/implementation.h" 限定
            );

public:
    /// 计算HMAC称签名(HMAC-SHA256)
    ///
    /// @return 二进制数据, 类型为 const vector<BYTE>& C++ 指针引用
    /// @throws std::exception 代表执行失败, 可能导致执行失败的原因包括: TPM设备应答异常, TPM资源管理器错误以及其他未知错误
    const std::vector<unsigned char>& HMAC_SHA256(
            const void *data, ///< 指向输入数据的指针
            unsigned short nDatalength, ///< 数据长度. 单位: 字节. 取值范围[0, 1024], 单条输入数据的长度上限受TSS和物理硬件共同限制, 实际上限有可能小于1024字节
            const void *key, ///< HMAC签名密钥值
            unsigned short nKeyLength ///< HMAC签名密钥长度. 单位: 字节. 取值范围[1, 128]. @note MAX_SYM_DATA=128 字节, 由 "sapi/implementation.h" 限定
            );

private:
    std::vector<unsigned char> m_hmacDigest;
};

#endif // __cplusplus
#endif // CALCULATOR_CLIENT_H_

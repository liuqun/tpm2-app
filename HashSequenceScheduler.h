// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef HASH_SEQUENCE_SCHEDULER_H_
#define HASH_SEQUENCE_SCHEDULER_H_

#include "sapi/tpm20.h"

class HashSequenceScheduler
{
public:
    HashSequenceScheduler(TSS2_SYS_CONTEXT *p);
    void start(TPMI_ALG_HASH algorithm, TPM2B_AUTH *pAuthValue);
    void update(const TPM2B_MAX_BUFFER *pMessagePacket);
    /**
     * Method complete()
     *
     * @param TPM2B_DIGEST *pOutputDigest - The output digest struct
     *  注意摘要内容的存储空间需经调用者预先分配,
     *  可以由该结构体首部的 2 字节 size 指示预先分配的空间大小,
     *  但函数内部具体实现有可能忽略 size 字段的具体内容,
     *  建议与其他厂家提供的 TSS 保持一致
     * @throw const char * - 字符串表示的错误信息, 只读, 字符串以 '\0' 结尾
     */
    void complete(TPM2B_DIGEST *pOutputDigest);
private:
    TSS2_SYS_CONTEXT *m_pSysContext;
    bool m_started;
    TPM2B_AUTH m_savedAuthValue;
    TPMI_DH_OBJECT m_savedSequenceHandle;
};

class HashSequenceStartCommand {
private:
    TPM2B_AUTH auth;
    TPMI_ALG_HASH hashAlg;
    TPMI_DH_OBJECT sequenceHandle;
    TPM_RC rc;

public:
    /**
     * 构造函数
     */
    HashSequenceStartCommand();

    /**
     * 析构函数
     */
    ~HashSequenceStartCommand();

    /**
     *
     */
    TPMI_ALG_HASH prepareHashAlgorithm(TPMI_ALG_HASH algorithm);

    /**
     *
     */
    const TPM2B_AUTH& prepareOptionalAuthValue(const BYTE value[], UINT16 size);

    /**
     *
     */
    void clearAuthValue();

    /**
     * 执行 TPM 命令
     */
    virtual void execute(TSS2_SYS_CONTEXT *pSysContext);

    /**
     * 取出最终哈希摘要计算结果数据缓冲区的长度, 单位字节
     *
     * @return 长度
     */
    TPMI_DH_OBJECT getHashSequenceHandle() const;
};

#endif /* HASH_SEQUENCE_SCHEDULER_H_ */

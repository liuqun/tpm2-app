/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef KEY_UTILITIES_H_
#define KEY_UTILITIES_H_

#include <sapi/tpm20.h>

#ifdef __cplusplus

/**
 * 访问密钥节点公开信息
 */
class KeyPublicDataReadingOperation {
private:
    TPMI_DH_OBJECT keyHandle;
    // 上面的成员变量用于保存输入参数
    // 下面的成员变量用于保存输出结果
public:
    TPM2B_PUBLIC keyPublicData; // 内部包含 TPM 定义的巨型数据结构
public:
    TPM2B_NAME keyName;
public:
    TPM2B_NAME qualifiedName;

public:
    TPM_RC rc;

public:
    KeyPublicDataReadingOperation();
    ~KeyPublicDataReadingOperation();

    /**
     * 通过句柄指定访问的密钥节点, 同时保存相应的访问授权数据
     *
     * @param handle 指定句柄, 取值一般为 0x81 或 0x80 开头
     * @return TPMI_DH_OBJECT 仅用于调试, 返回值总是等于参数列表中指定的句柄
     */
    TPMI_DH_OBJECT setKeyHandle(TPMI_DH_OBJECT handle);

    /**
     * 执行 TPM 命令
     */
    void execute(TSS2_SYS_CONTEXT *pSysContext);

    /**
     * 取回命令应答结果中的密钥唯一名字
     */
    const TPM2B_NAME& getKeyName();
};

// ============================================================================

/**
 * 密钥加载助手
 * @brief 帮助开发者更轻松地调用 Tss2_Sys_Load() 完成任意密钥的加载操作.
 *        成员变量包括Tss2_Sys_Load() 所需准备的
 */
class KeyLoadingOperation {
public:
    TPMI_DH_OBJECT	parentHandle; // 记录创建密钥时需要指定的密钥树父节点位置
    TPMS_AUTH_COMMAND parentAuthSettings; // 密钥树父节点的访问授权方式
    TPMS_AUTH_RESPONSE m_sessionDataOut[3]; // OUT

    // 用于保存输输出参数的成员变量
    TPM_HANDLE keyHandle; // OUT
    TPM2B_NAME keyName; // OUT

public:
    TSS2_RC rc;

public:
    KeyLoadingOperation();
    ~KeyLoadingOperation();

public:
    TPMI_DH_OBJECT setParentHandleWithoutAuthValue(
            TPMI_DH_OBJECT parentHandle /** 父句柄 */
            );
    TPMI_DH_OBJECT setParentHandleWithAuthPassword(
            TPMI_DH_OBJECT parentHandle, /** 父句柄 */
            const BYTE authValue[], /** 句柄授权数据 */
            UINT16 size /** 数据长度 */
            );
    void clearSensitiveAuthValues(); /** 清除访问父句柄用的密码 */

public:
    /**
     * 加载已创建的密钥对象
     *
     * @brief 密钥必须经过 TPM 加载才能用与计算
     */
    void loadExistingKey(
            TSS2_SYS_CONTEXT *pSysContext, /** system api 上下文指针 */
            const TPM2B_PRIVATE& inPrivate, /** 需要引用Create命令的输出数据 */
            const TPM2B_PUBLIC& inPublic /** 需要引用Create命令的输出数据 */
            );
};

// ============================================================================

/**
 * HMAC密钥创建助手工具
 *
 * @brief 该助手类提供一组成员函数快速填写所有中间参数, 帮助开发者更轻松地
 *        调用 TSS 接口函数, 完成 HMAC 密钥的创建.
 */
class HMACKeyCreationOperation {
public:
    TPMI_DH_OBJECT	parentHandle; /** 记录创建密钥时需要指定的密钥树父节点位置 */
    TPMS_AUTH_COMMAND parentAuthSettings; /** 密钥树父节点的访问授权方式 */
    TPMS_AUTH_COMMAND sensitiveParameterProtectionAuthSettings; /** 设置 TPM 报文收发敏感参数时是否进行加密保护 */
    uint8_t m_cmdAuthsCount; // 取值范围: 1-2

    // 用于保存 TPM 应答桢中的授权数据
    TPMS_AUTH_RESPONSE m_sessionDataOut[3];
    uint8_t m_rspAuthsCount;  // 取值范围: 1-2

    // 用于保存输入参数的成员变量
    TPM2B_SENSITIVE_CREATE inSensitive;
    TPM2B_PUBLIC inPublic;
    TPM2B_DATA outsideInfo;
    TPML_PCR_SELECTION creationPCR;

    // 用于保存输出参数的成员变量
    TPM2B_PRIVATE outPrivate; // 输出-1: 下一步密钥树节点加载时会用到
    TPM2B_PUBLIC outPublic; // 输出-2 下一步密钥树节点加载时会用到
    TPM2B_CREATION_DATA creationData; // 输出-3
    TPM2B_DIGEST creationHash; // 输出-4
    TPMT_TK_CREATION creationTicket; // 输出-5

public:
    TSS2_RC rc;

public:
    HMACKeyCreationOperation();
    ~HMACKeyCreationOperation();
    TPMI_DH_OBJECT setParentHandleWithoutAuthValue(
            TPMI_DH_OBJECT parentHandle /** 父句柄 */
            );
    TPMI_DH_OBJECT setParentHandleWithAuthPassword(
            TPMI_DH_OBJECT parentHandle, /** 父句柄 */
            const BYTE authValue[], /** 句柄授权数据 */
            UINT16 size /** 数据长度 */
            );
    void clearSensitiveAuthValues(); /** 清除访问父句柄用的密码 */

    /**
     * 指定密码和额外的敏感数据
     *
     * @param keyAuthValue 为即将创建的新密钥节点指定一个授权密码
     * @param size 授权值字节数, 可以等于0
     * @param extraDataSize 可以等于0
     * @param extraSensitiveData 当 extraDataSize == 0 时, 该指针将被忽略
     */
    const TPM2B_SENSITIVE_CREATE& setSensitiveParameters(
            /* 指定子节点的授权值 */
            const BYTE keyAuthValue[],
            UINT16 size,
            /* 附加一些额外的初始值用于创建密钥 */
            const BYTE extraSensitiveData[],
            UINT16 extraDataSize // 附加敏感数据, 长度可以为空
    );
    void clearSensitiveParameters(); /** 清除前一个函数指定的节点授权访问密+额外的敏感数据 */

    /**
     * 指定生成密钥树节点名称时采用哈希算法
     * 注意这里不是指定 HMAC 运算所要采用的哈希算法
     *
     * @param keyNameHashAlg 备选值包括:
     *  TPM_ALG_SHA1
     *  TPM_ALG_SHA256
     *  TPM_ALG_SHA384
     *  TPM_ALG_SHA512
     *  TPM_ALG_SM3_256
     *  以及默认值 TPM_ALG_NULL (表示不进行哈希)
     * @return 返回所选择的哈希算法, 该返回值仅为方便调试
     */
    TPMI_ALG_HASH setKeyNameHashAlgorithm(TPMI_ALG_HASH keyNameHashAlg);

    /**
     * 选择 HMAC 运算所使用的哈希算法
     *
     * @param hashAlg 备选值包括:
     *  TPM_ALG_SHA1
     *  TPM_ALG_SHA256
     *  TPM_ALG_SHA384
     *  TPM_ALG_SHA512
     *  TPM_ALG_SM3_256
     *  以及默认值 TPM_ALG_NULL (表示不进行哈希)
     * @return 返回所选择的哈希算法, 该返回值仅为方便调试
     */
    TPMI_ALG_HASH setHashAlgorithm(TPMI_ALG_HASH hashAlg);

    /**
     * 创建密钥
     *
     * @param pSysContext system api 上下文指针
     */
    void createKey(TSS2_SYS_CONTEXT *pSysContext);
};

#endif // __cplusplus
#endif // KEY_UTILITIES_H_


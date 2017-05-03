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
            const TPM2B_PRIVATE& keyPrivate, /** 需要引用Create命令的输出数据 */
            const TPM2B_PUBLIC& keyPublic /** 需要引用Create命令的输出数据 */
            );
};

#endif // __cplusplus
#endif // KEY_UTILITIES_H_


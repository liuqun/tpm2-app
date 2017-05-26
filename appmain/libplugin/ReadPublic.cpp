/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// ============================================================================
// 自定义输入输出参数格式
// ============================================================================

/// 私有结构体 ReadPublic_In
typedef struct Parameters_In {
    TPMI_DH_OBJECT objectHandle;
} ReadPublic_In;

/// 私有结构体 ReadPublic_Out
typedef struct Parameters_Out {
    TPM2B_PUBLIC outPublic;
    TPM2B_NAME name;
    TPM2B_NAME qualifiedName;
} ReadPublic_Out;

// ============================================================================
// 构造函数
// ============================================================================
ReadPublic::ReadPublic() {
    m_in = new ReadPublic_In;
    m_out = new ReadPublic_Out;

    /* 设置默认句柄 */
    m_in->objectHandle = (TPMI_DH_OBJECT) 0x80000000; // FIXME: 此句柄初始值一般会指向 TPM 模块加载的第一个密钥. 用户应该自己指定密钥句柄 @see ReadPublic::configObject()

    /* 清空输出缓冲区 */
    memset(m_out, 0x00, sizeof(*m_out));

    m_cmdAuthsCount = 0; // 读公开信息时不需要授权
}

// ============================================================================
// 析构函数
// ============================================================================
ReadPublic:: ~ReadPublic() {
    delete m_in;
    delete m_out;
}

// ============================================================================
// 指定被查询的对象
// ============================================================================
void ReadPublic::configObject(TPMI_DH_OBJECT objectHandle) {
    m_in->objectHandle = objectHandle;
}

// ============================================================================
// 组建命令帧报文
// ============================================================================
void ReadPublic::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_ReadPublic_Prepare(// NOTE: 此处应检查函数返回值
            ctx,
            m_in->objectHandle
            );
    // 然后显式调用父类的成员函数(注: ReadPublic 命令本身无需授权, 预留此接口仅用于HMAC校验或参数加解密)
    this->TPMCommand::buildCmdPacket(ctx);
}

// ============================================================================
// 解码应答桢报文
// ============================================================================
void ReadPublic::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先显式调用父类的成员函数(注: ReadPublic 命令本身无需授权, 预留此接口仅用于HMAC校验或参数加解密)
    this->TPMCommand::unpackRspPacket(ctx);
    // 然后调用 API 函数进行解包
    m_out->outPublic.t.size = 0;// 此处必须填零: @see Unmarshal_TPM2B_PUBLIC() TSS2_SYS_RC_BAD_VALUE
    m_out->name.t.size = sizeof(m_out->name.t.name);
    m_out->qualifiedName.t.size = sizeof(m_out->qualifiedName.t.name);
    Tss2_Sys_ReadPublic_Complete(// NOTE: 此处应检查函数返回值
            ctx,
            &(m_out->outPublic),
            &(m_out->name),
            &(m_out->qualifiedName)
            );
}

// ============================================================================
// 输出读取结果的第一部分 Public Area
// ============================================================================
const TPMT_PUBLIC& ReadPublic::outPublicArea() {
    return m_out->outPublic.t.publicArea;
}

// ============================================================================
// 输出读取结果的第二部分 Name
// ============================================================================
const TPM2B_NAME& ReadPublic::outName() {
    return m_out->name;
}

// ============================================================================
// 输出读取结果的第三部分 QN(Qualified Name)
// ============================================================================
const TPM2B_NAME& ReadPublic::outQualifiedName() {
    return m_out->qualifiedName;
}

// ============================================================================
// 擦除临时缓存的输出数据
// ============================================================================
void ReadPublic::eraseCachedOutputData() {
    memset(m_out, 0x00, sizeof(*m_out));
}

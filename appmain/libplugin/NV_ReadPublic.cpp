/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// ============================================================================
// 自定义输入输出参数格式
// ============================================================================

/// 私有结构体 NV_ReadPublic_In
typedef struct Parameters_In {
    TPMI_RH_NV_INDEX nvIndex;
} NV_ReadPublic_In;

/// 私有结构体 NV_ReadPublic_Out
typedef struct Parameters_Out {
    TPM2B_NV_PUBLIC nvPublic;
    TPM2B_NAME nvName;
} NV_ReadPublic_Out;

// ============================================================================
// 构造函数
// ============================================================================
NV::ReadPublic::ReadPublic() {
    m_in = new NV_ReadPublic_In;
    m_out = new NV_ReadPublic_Out;

    /* 设置默认句柄 */
    m_in->nvIndex = NV_INDEX_FIRST; /// @see NV_INDEX_FIRST: 0x01000000

    /* 清空输出缓冲区 */
    memset(m_out, 0x00, sizeof(*m_out));

    m_cmdAuthsCount = 0; // 读公开信息时默认不需要提供授权内容
}

// ============================================================================
// 析构函数
// ============================================================================
NV::ReadPublic:: ~ReadPublic() {
    delete m_in;
    delete m_out;
}

// ============================================================================
// 指定要访问的 NV Index
// ============================================================================
void NV::ReadPublic::configNVIndex(TPMI_RH_NV_INDEX index) {
    m_in->nvIndex = index;
}

// ============================================================================
// 组建命令帧报文
// ============================================================================
void NV::ReadPublic::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_NV_ReadPublic_Prepare( // NOTE: 此处应检查函数返回值
            ctx,
            m_in->nvIndex
            );
    // 然后显式调用父类的成员函数(注: NV::ReadPublic 命令本身无需授权, 预留此接口仅用于HMAC校验或参数加解密)
    this->TPMCommand::buildCmdPacket(ctx);
}

// ============================================================================
// 解码应答桢报文
// ============================================================================
void NV::ReadPublic::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先显式调用父类的成员函数(注: NV::ReadPublic 命令本身无需授权, 预留此接口仅用于HMAC校验或参数加解密)
    this->TPMCommand::unpackRspPacket(ctx);
    // 然后调用 API 函数进行解包
    m_out->nvPublic.t.size = 0; // 此处必须填零: @see Unmarshal_TPM2B_NV_PUBLIC() TSS2_SYS_RC_BAD_VALUE
    m_out->nvName.t.size = sizeof(m_out->nvName.t.name);
    Tss2_Sys_NV_ReadPublic_Complete( // NOTE: 此处应检查函数返回值
            ctx,
            &(m_out->nvPublic),
            &(m_out->nvName)
            );
}

// ============================================================================
// 输出读取结果的第一部分 NV Public Area
// ============================================================================
const TPMS_NV_PUBLIC& NV::ReadPublic::resultNVPublicArea() {
    return m_out->nvPublic.t.nvPublic;
}

// ============================================================================
// 输出读取结果的第二部分 NV Name
// ============================================================================
const TPM2B_NAME& NV::ReadPublic::resultNVName() {
    return m_out->nvName;
}

// ============================================================================
// 擦除临时缓存的输出数据
// ============================================================================
void NV::ReadPublic::eraseCachedOutputData(){
    memset(m_out, 0x00, sizeof(*m_out));
}

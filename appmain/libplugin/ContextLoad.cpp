/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// 私有结构体
typedef struct In {
    TPMS_CONTEXT context;
} ContextLoad_In;

// 私有结构体
typedef struct Out{
    TPMI_DH_CONTEXT	loadHandle;
} ContextLoad_Out;

// ----------------------------------------------------------------------------

// 构造函数
ContextLoad::ContextLoad() {
    m_in = new ContextLoad_In;
    m_out = new ContextLoad_Out;
    memset(m_in, 0x00, sizeof(*m_in));
    memset(m_out, 0x00, sizeof(*m_out));
    m_cmdAuthsCount = 0;
}

// 析构函数
ContextLoad::~ContextLoad() {
    delete m_in;
    delete m_out;
}

// 填写之前导出的对象上下文(用于恢复原始对象)
void ContextLoad::configContext(UINT64 sequence,
        TPMI_DH_CONTEXT savedHandle,
        TPMI_RH_HIERARCHY hierarchy,
        const TPM2B_CONTEXT_DATA& contextBlob
        ) {
    m_in->context.sequence = sequence;
    m_in->context.savedHandle = savedHandle;
    m_in->context.hierarchy = hierarchy;
    m_in->context.contextBlob.t.size = contextBlob.t.size;
    memcpy(m_in->context.contextBlob.t.buffer, contextBlob.t.buffer, sizeof(m_in->context.contextBlob.t.buffer));
}

// 填写之前导出的对象上下文(用于恢复原始对象)
void ContextLoad::configContext(const TPMS_CONTEXT& context) {
    memcpy(&(m_in->context), &context, sizeof(TPMS_CONTEXT));
}

// 组建命令帧报文
void ContextLoad::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    Tss2_Sys_ContextLoad_Prepare( // NOTE: 此处应检查函数返回值
            ctx, &(m_in->context));
}

// 解码应答帧报文
void ContextLoad::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    Tss2_Sys_ContextLoad_Complete( // NOTE: 此处应检查函数返回值
            ctx, &(m_out->loadHandle));
}

// 输出对象上下文
TPM_HANDLE ContextLoad::outHandle() {
    return m_out->loadHandle;
}

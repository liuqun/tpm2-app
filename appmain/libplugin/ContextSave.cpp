/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <cstdio>
#include <stdexcept>
using std::invalid_argument;
#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// 私有结构体
typedef struct In {
    TPMI_DH_CONTEXT	saveHandle;
} ContextSave_In;

// 私有结构体
typedef struct Out{
    TPMS_CONTEXT context;
} ContextSave_Out;

// ----------------------------------------------------------------------------

// 构造函数
ContextSave::ContextSave() {
    m_in = new ContextSave_In;
    m_out = new ContextSave_Out;
    memset(m_out, 0x00, sizeof(*m_out));
    m_cmdAuthsCount = 0;
}

// 析构函数
ContextSave::~ContextSave() {
    delete m_in;
    delete m_out;
}

// 配置要存储的对象句柄
void ContextSave::configHandle(TPM_HANDLE handle) {
    // 首先应检查句柄类型
    const UINT8 ht = (UINT8) (handle >> HR_SHIFT); ///< handle type
    if (   (ht >= TPM_HT_TRANSIENT && ht <= TPM_HT_PERSISTENT)
        || (ht >= TPM_HT_HMAC_SESSION && ht <= TPM_HT_POLICY_SESSION)) {
        // 密钥句柄的高八位以0x80或0x81开始
        // 会话句柄的高八位以0x02或0x03开始
        m_in->saveHandle = (TPMI_DH_CONTEXT) handle;
    } else { // 以其他数字开头的句柄都无效
        char msg[256];
        const size_t MaxLen = sizeof(msg);
        snprintf(msg, MaxLen, "Invalid handle 0x%08X (Type 0x%02X is neither a TPM object handle nor a session handle)", (UINT32)handle, ht);
        throw std::invalid_argument(msg);
    }
}

// 组建命令帧报文
void ContextSave::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    Tss2_Sys_ContextSave_Prepare( // NOTE: 此处应检查函数返回值
            ctx, m_in->saveHandle);
}

// 解码应答帧报文
void ContextSave::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    Tss2_Sys_ContextSave_Complete( // NOTE: 此处应检查函数返回值
            ctx, &(m_out->context));
}

// 输出对象上下文
const TPMS_CONTEXT& ContextSave::outContext() {
    return m_out->context;
}

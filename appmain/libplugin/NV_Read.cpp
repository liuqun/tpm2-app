/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// ============================================================================
// 自定义输入输出参数格式
// ============================================================================

/// 私有结构体 NV_Read_In
typedef struct In {
    TPMI_RH_NV_AUTH authHandle;
    TPMI_RH_NV_INDEX nvIndex;
    UINT16 size;
    UINT16 offset;
} NV_Read_In;

/// 私有结构体 NV_Read_Out
typedef struct Out {
    TPM2B_MAX_NV_BUFFER data;
} NV_Read_Out;

// ============================================================================
// 构造函数
// ============================================================================
NV::Read::Read() {
    m_in = new NV_Read_In;
    m_out = new NV_Read_Out;

    /* 设置读写 NV 空间的默认参数 */
    m_in->authHandle = TPM_RH_PLATFORM;
    m_in->nvIndex = NV_INDEX_FIRST; /// @see NV_INDEX_FIRST: 0x01000000
    m_in->size = 0;
    m_in->offset = 0;

    /* 清空输出缓冲区 */
    memset(&m_out->data, 0x00, sizeof(m_out->data));

    m_cmdAuthsCount = 1; // 默认值
    m_sendAuthValues[0].sessionHandle = TPM_RS_PW;
    m_sendAuthValues[0].hmac.t.size = 0;
}

// ============================================================================
// 析构函数
// ============================================================================
NV::Read:: ~Read() {
    eraseCachedPassword();
    eraseCachedOutputData();
    delete m_in;
    delete m_out;
}

// ============================================================================
// 指定要访问的 NV Index, 数据总长度以及起始偏移量
// ============================================================================
void NV::Read::configNVIndex(TPMI_RH_NV_INDEX index, UINT16 dataSize, UINT16 offset) {
    m_in->authHandle = index; ///< 授权句柄默认一般填写 NV Index 本身, 可选取值包括: NV Index 本身, TPM_RH_PLATFORM, TPM_RH_OWNER
    m_in->nvIndex = index;
    m_in->size = dataSize;
    m_in->offset = offset;
}

// ============================================================================
// 指定访问授权方式
// ============================================================================
void NV::Read::configNVIndexAuthSession(
        TPMI_SH_AUTH_SESSION authSessionHandle ///< 会话句柄, 可选取值包括: 明文密码授权会话句柄 TPM_RS_PW, 其他 HMAC/Policy 会话句柄
        ) {
    m_sendAuthValues[0].sessionHandle = authSessionHandle;
}

// ============================================================================
// 保存 NV 访问密码
// ============================================================================
void NV::Read::configNVIndexPassword(
        const void *password, ///< 句柄授权数据
        UINT16 length ///< 授权数据长度
        ) {
    TPMS_AUTH_COMMAND& cmdAuth ///< an alias for m_sendAuthValues[0]
            =m_sendAuthValues[0];

    cmdAuth.nonce.t.size = 0;
    cmdAuth.sessionAttributes.val = 0;
    if (length > sizeof(cmdAuth.hmac.t.buffer)) {
        length = sizeof(cmdAuth.hmac.t.buffer); // 舍弃过长的字符, 防止溢出
    }
    memcpy((void *) cmdAuth.hmac.t.buffer, (void *) password, length);
    cmdAuth.hmac.t.size = length;
}

// ============================================================================
// 擦除临时缓存的 NV 访问密码
// ============================================================================
void NV::Read::eraseCachedPassword() {
    TPMS_AUTH_COMMAND& cmdAuth=m_sendAuthValues[0];
    memset((void *) cmdAuth.hmac.t.buffer, 0x00, sizeof(cmdAuth.hmac.t.buffer));
    cmdAuth.hmac.t.size = 0;
}

// ============================================================================
// 组建命令帧报文
// ============================================================================
void NV::Read::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_NV_Read_Prepare( // NOTE: 此处应检查函数返回值
            ctx,
            m_in->authHandle,
            m_in->nvIndex,
            m_in->size,
            m_in->offset
            );
    // 然后显式调用父类的成员函数, 设置命令帧的 auth value
    this->TPMCommand::buildCmdPacket(ctx);
}

// ============================================================================
// 解码应答桢报文
// ============================================================================
void NV::Read::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先显式调用父类的成员函数, 解码应答桢的 auth value
    this->TPMCommand::unpackRspPacket(ctx);
    // 然后调用 API 函数进行解包
    m_out->data.t.size = sizeof(m_out->data.t.buffer);
    Tss2_Sys_NV_Read_Complete(ctx, &(m_out->data)); // NOTE: 此处应检查函数返回值
}

// ============================================================================
// 按 TPM2B_MAX_NV_BUFFER 格式输出 NV 读取结果
// ============================================================================
const TPM2B_MAX_NV_BUFFER& NV::Read::outData() {
    return m_out->data;
}

// ============================================================================
// 擦除临时缓存的输出数据
// ============================================================================
void NV::Read::eraseCachedOutputData(){
    memset(m_out, 0x00, sizeof(*m_out));
}

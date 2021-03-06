/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

typedef struct In {
    TPMI_RH_PROVISION authHandle;
    TPM2B_AUTH auth; ///< 此处保存的时新定义的 NV Index 本身的访问密码, 不是父句柄的访问密码
    TPM2B_NV_PUBLIC publicInfo;
} NV_DefineSpace_In;

static
TPMI_RH_PROVISION GetDefaultAuthHandle() {
    return TPM_RH_PLATFORM; // @see TPMA_NV_PLATFORMCREATE 和 GetDefaultAttributesVal()
}

static
UINT32 GetDefaultAttributesVal() {
    TPMA_NV defaultAttributes;

    defaultAttributes.val = 0; // 先清除标所有记位
    // 预设以下标志位:
    defaultAttributes.TPMA_NV_AUTHREAD = 1;  // 定义读NV数据时是否需要授权
    defaultAttributes.TPMA_NV_AUTHWRITE = 1;  // 定义写NV数据时是否需要授权
    defaultAttributes.TPMA_NV_PLATFORMCREATE = 1; // 是否只允许 Platform 创建和销毁 NV Index 对象. Owner 不能销毁 Platform 创建的 NV Index. 反过来 Platform 也不能销毁 Owner 创建的 NV Index
    defaultAttributes.TPMA_NV_ORDERLY = 1; // 是否允许 TPM 模块留待最后执行下一条 Shutdown 命令时再将数据统一写入 NV Chip. 此标志位设计意图在于减少读写 NV 存储器硬件的频率(优化 IO 效率)
    return defaultAttributes.val;
}

NV::DefineSpace::DefineSpace() {
    m_in = new NV_DefineSpace_In;

    m_cmdAuthsCount = 1; // 默认值
    m_in->authHandle = GetDefaultAuthHandle();

    /* 设置 NV 空间的默认参数 */
    m_in->publicInfo.t.size = sizeof(TPMI_RH_NV_INDEX) + sizeof(TPMI_ALG_HASH)
            + sizeof(TPMA_NV) + sizeof(UINT16) + sizeof(UINT16);

    m_in->publicInfo.t.nvPublic.nvIndex = 0x01500000; // 默认值
    m_in->publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA1; // 默认值(FIXME: SHA1 哈希算法过时了, 强度不足以抵御攻击)
    m_in->publicInfo.t.nvPublic.attributes.val = GetDefaultAttributesVal();
    m_in->publicInfo.t.nvPublic.authPolicy.t.size = 0;
    m_in->publicInfo.t.nvPublic.dataSize = 0;
}

void NV::DefineSpace::configCreatorAsPlatform() {
    m_in->authHandle = TPM_RH_PLATFORM;
    m_in->publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1; // 是否只允许 Platform 创建和销毁 NV Index 对象. Owner 不能销毁 Platform 创建的 NV Index.
}

void NV::DefineSpace::configCreatorAsOwner() {
    m_in->authHandle = TPM_RH_OWNER;
    m_in->publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 0; // 是否只允许 Platform 创建和销毁 NV Index 对象. Platform 也不能销毁 Owner 创建的 NV Index
}

void NV::DefineSpace::configNVIndex(TPMI_RH_NV_INDEX index) {
    m_in->publicInfo.t.nvPublic.nvIndex = index; // TODO: 应检查参数的极限取值范围
}

void NV::DefineSpace::configNVIndexDataSize(UINT16 dataSize) {
    m_in->publicInfo.t.nvPublic.dataSize = dataSize; // TODO: 应检查参数的极限取值范围
}

void NV::DefineSpace::configNVIndexAuthPassword(
        const void *authPassword, ///< 密码
        UINT16 len ///< 密码长度
        ) {
    if (len > sizeof(m_in->auth.t.buffer)) {
        len = sizeof(m_in->auth.t.buffer); // 舍弃过长的字符, 防止内存读写越界
    }
    m_in->auth.t.size = len;
    memcpy((void *) m_in->auth.t.buffer, authPassword, len);
}

void NV::DefineSpace::eraseCachedNVIndexAuthPassword() {
    memset((void *) m_in->auth.t.buffer, 0x00, sizeof(m_in->auth.t.buffer));
    m_in->auth.t.size = 0;
}

void NV::DefineSpace::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 调用 API
    Tss2_Sys_NV_DefineSpace_Prepare(ctx,
            m_in->authHandle,
            &m_in->auth,
            &m_in->publicInfo);
    // 最后通过显式调用父类的成员函数, 设置命令帧的 auth value
    this->TPMCommand::buildCmdPacket(ctx);
    // @note 必须在调用 API 函数 Tss2_Sys_NV_DefineSpace_Prepare() 填写了输入参数之后才能调用 TPMCommand::buildCmdPacket(), 因 buildCmdPacket() 将在其内部调用 Tss2_Sys_SetCmdAuths(),
    // 这是由于底层 API 接口设计不良导致的, 我们作为二次开发者调用这些 API 时次序必须严格满足底层 API 的要求
}

NV::DefineSpace::~DefineSpace() {
    eraseCachedNVIndexAuthPassword();
    delete m_in;
}

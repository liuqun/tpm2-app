/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// ============================================================================
// 自定义输入输出参数格式
// ============================================================================

/// 私有结构体 Load_In
typedef struct Parameters_In {
    TPMI_DH_OBJECT parentHandle; ///< 输入父节点句柄. 记录父节点的句柄编号
    TPM2B_PRIVATE *inPrivate; ///< 输入指针, 指向密钥的私密信息结构体
    TPM2B_PUBLIC *inPublic; ///< 输入指针, 指向密钥的公开信息结构体
} Load_In;

/// 提供一个未定义的数据块, 让指针 inPrivate 和 inPublic 的初始值指向这里
static TPM2B UNDEFINED = {
    .size = 0,
    .buffer = {'\0'},
};

/// 私有结构体 Load_Out
typedef struct Parameters_Out {
    TPM_HANDLE objectHandle; ///< 输出节点句柄, 密钥被成功加载之后应通过该句柄访问
    TPM2B_NAME name; ///< 输出结构体, 密钥名
} Load_Out;

// ============================================================================
// 构造函数
// ============================================================================
Load::Load() {
    m_in = new Load_In;
    m_out = new Load_Out;

    /* 设置默认句柄 */
    m_in->parentHandle = (TPMI_DH_OBJECT) 0x80000000;

    /* 输入参数指针初始值指向未定义的空白 TPM2B 区域 */
    m_in->inPrivate = (TPM2B_PRIVATE *) &UNDEFINED; // 这里我们提供了一个空白初始值, 而不是简单粗暴地设置为 NULL
    m_in->inPublic = (TPM2B_PUBLIC *) &UNDEFINED; // 同上

    /* 清空输出缓冲区 */
    memset(m_out, 0x00, sizeof(*m_out));

    m_cmdAuthsCount = 1; // 需经密钥树父节点授权方可加载子节点
}

// ============================================================================
// 析构函数
// ============================================================================
Load:: ~Load() {
    eraseCachedAuthPassword();
    m_in->inPrivate = NULL; // 为避免泄露敏感信息, 建议析构时将指针设置为 NULL
    delete m_in;
    delete m_out;
}

// ============================================================================
// 指定通过密钥树中哪个父节点进行授权校验
// ============================================================================
void Load::configAuthParent(TPMI_DH_OBJECT parentHandle) {
    m_in->parentHandle = parentHandle;
}

// ============================================================================
// 指定访问授权方式(通过哪种会话进行授权校验)
// ============================================================================
void Load::configAuthSession(
        TPMI_SH_AUTH_SESSION authSessionHandle ///< 会话句柄, 可选取值包括: 明文密码授权会话句柄 TPM_RS_PW, 其他 HMAC/Policy 会话句柄
        ) {
    m_sendAuthValues[0].sessionHandle = authSessionHandle;
}

// ============================================================================
// 指定授权值访问密码(属于敏感数据)
// ============================================================================
void Load::configAuthPassword(const void *password, UINT16 length) {
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
// 擦除临时缓存的授权值
// ============================================================================
void Load::eraseCachedAuthPassword() {
    TPMS_AUTH_COMMAND& cmdAuth ///< an alias for m_sendAuthValues[0]
            =m_sendAuthValues[0];
    memset((void *) cmdAuth.hmac.t.buffer, 0x00, sizeof(cmdAuth.hmac.t.buffer));
    cmdAuth.hmac.t.size = 0;
}

// ============================================================================
// 指定要加载的密钥的私钥数据(属于敏感数据)
// ============================================================================
void Load::configPrivateData(const TPM2B_PRIVATE& inPrivate) {
    m_in->inPrivate = (TPM2B_PRIVATE *) &inPrivate;
}

// ============================================================================
// 指定要加载的密钥的公开数据(非敏感)
// ============================================================================
void Load::configPublicData(const TPM2B_PUBLIC& inPublic) {
    m_in->inPublic = (TPM2B_PUBLIC *) &inPublic;
}

// ============================================================================
// 组建命令帧报文
// ============================================================================
void Load::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先调用底层 API 填写输入参数
    Tss2_Sys_Load_Prepare(// NOTE: 此处应检查函数返回值
            ctx,
            m_in->parentHandle,
            m_in->inPrivate,
            m_in->inPublic
            );
    // 然后显式调用父类的成员函数完成填写 AuthValue 工作
    this->TPMCommand::buildCmdPacket(ctx);
}

// ============================================================================
// 解码应答桢报文
// ============================================================================
void Load::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
    // 先显式调用父类的成员函数(通过该函数写入授权值)
    this->TPMCommand::unpackRspPacket(ctx);
    // 然后调用 API 函数进行解包
    m_out->objectHandle = 0xFF000000; // DEBUG ONLY
    m_out->name.t.size = sizeof(m_out->name.t.name);
    Tss2_Sys_Load_Complete(// NOTE: 此处应检查函数返回值
            ctx,
            &(m_out->objectHandle),
            &(m_out->name)
            );
}

// ============================================================================
// 命令输出结果的第一部分: 取回新节点的 Object Handle
// ============================================================================
TPM_HANDLE Load::resultObjectHandle() {
    return m_out->objectHandle;
}

// ============================================================================
// 命令输出结果的第二部分: 新节点的节点名
// ============================================================================
const TPM2B_NAME& Load::resultName() {
    return m_out->name;
}

// ============================================================================
// 擦除临时缓存的输出数据, 同时清零其他成员函数返回的只读数据块的值.
// 均为非敏感数据
// ============================================================================
void Load::eraseCachedOutputData() {
    memset(m_out, 0x00, sizeof(*m_out));
}

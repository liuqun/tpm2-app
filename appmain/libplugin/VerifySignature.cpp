/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

// ============================================================================
// 自定义输入输出参数格式
// ============================================================================

/// 私有结构体
typedef struct In {
    TPMI_DH_OBJECT keyHandle;
    TPM2B_DIGEST digest;
    TPMT_SIGNATURE signature;
} VerifySignature_In;

/// 私有结构体
typedef struct Out {
    TPMT_TK_VERIFIED validation;
} VerifySignature_Out;

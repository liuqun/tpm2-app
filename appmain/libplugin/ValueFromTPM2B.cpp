/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"

// ============================================================================
// 提供一组 TPM2B_* 数据转换工具(C++ 接口)
// ============================================================================

/** TPMU_NAME from TPM2B_NAME */
const TPMU_NAME& ValueFromTPM2B(const TPM2B_NAME& name) {
    const TPMU_NAME *p = (const TPMU_NAME *) (name.t.name);
    return *p;
}

// ============================================================================
// 提供一组 TPM2B_* 数据转换工具(C 接口)
// ============================================================================

/** TPMU_NAME from TPM2B_NAME */
const TPMU_NAME *TPMU_NAME__From__TPM2B_NAME(const TPM2B_NAME *pName) {
    return (const TPMU_NAME *) (pName->t.name);
}

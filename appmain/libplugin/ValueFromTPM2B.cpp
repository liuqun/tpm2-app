/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"

// ============================================================================
// 提供一组 TPM2B_* 数据转换工具(C++ 接口)
// ============================================================================

/** TPMU_ENCRYPTED_SECRET from TPM2B_ENCRYPTED_SECRET */
const TPMU_ENCRYPTED_SECRET& ValueFromTPM2B(const TPM2B_ENCRYPTED_SECRET& secret) {
    const TPMU_ENCRYPTED_SECRET *p = (const TPMU_ENCRYPTED_SECRET *) (secret.t.secret);
    return *p;
}

/** TPMU_NAME from TPM2B_NAME */
const TPMU_NAME& ValueFromTPM2B(const TPM2B_NAME& name) {
    const TPMU_NAME *p = (const TPMU_NAME *) (name.t.name);
    return *p;
}

/** BYTE from TPM2B */
const BYTE *ValueFromTPM2B(const TPM2B& data) {
    return data.buffer;
}

/** BYTE from TPM2B_MAX_NV_BUFFER */
const BYTE *ValueFromTPM2B(const TPM2B_MAX_NV_BUFFER& block) {
    return block.b.buffer;
}

// ============================================================================
// 提供一组 TPM2B_* 数据转换工具(C 接口)
// ============================================================================

/** TPMU_ENCRYPTED_SECRET from TPM2B_ENCRYPTED_SECRET */
const TPMU_ENCRYPTED_SECRET *TPMU_ENCRYPTED_SECRET__From__TPM2B_ENCRYPTED_SECRET(
        const TPM2B_ENCRYPTED_SECRET *pSecret
        ) {
    return (const TPMU_ENCRYPTED_SECRET *) (pSecret->t.secret);
}

/** TPMU_NAME from TPM2B_NAME */
const TPMU_NAME *TPMU_NAME__From__TPM2B_NAME(const TPM2B_NAME *pName) {
    return (const TPMU_NAME *) (pName->t.name);
}

/** BYTE from TPM2B */
const BYTE *BYTE__From__TPM2B(const TPM2B *pData) {
    return pData->buffer;
}

/** BYTE from TPM2B_MAX_NV_BUFFER */
const BYTE *BYTE__From__TPM2B_MAX_NV_BUFFER(const TPM2B_MAX_NV_BUFFER *pBlock) {
    return pBlock->b.buffer;
}

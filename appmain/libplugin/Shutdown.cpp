/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"

using namespace TPMCommands;

typedef struct In {
    TPM_SU shutdownType;
} Shutdown_In;

Shutdown::Shutdown() {
    m_in = new Shutdown_In;
    m_in->shutdownType = TPM_SU_CLEAR;
}

void Shutdown::enbleRestoreSavedState() {
    m_in->shutdownType = TPM_SU_STATE;
}

void Shutdown::disableRestoreSavedState() {
    m_in->shutdownType = TPM_SU_CLEAR;
}

void Shutdown::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    Tss2_Sys_Startup_Prepare(ctx, m_in->shutdownType);
}

Shutdown::~Shutdown() {
    delete m_in;
}

/* encoding: utf-8 */
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"
using namespace TPMCommands;

typedef struct Parameters_In {
    TPM_SU startupType;
} Startup_In;

Startup::Startup() {
    m_in = new Startup_In;
    m_in->startupType = TPM_SU_CLEAR;
}

void Startup::enbleRestoreSavedState() {
    m_in->startupType = TPM_SU_STATE;
}

void Startup::disableRestoreSavedState() {
    m_in->startupType = TPM_SU_CLEAR;
}

void Startup::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
    Tss2_Sys_Startup_Prepare(ctx, m_in->startupType);
}

Startup::~Startup() {
    delete m_in;
}

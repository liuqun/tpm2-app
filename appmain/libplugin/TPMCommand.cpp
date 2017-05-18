/* encoding: utf-8 */
/// @file TPMCommand.cpp
/// @copyright Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
/// All rights reserved.

#include <sapi/tpm20.h>
#include "TPMCommand.h"

TPMCommand::TPMCommand() {
    m_in = NULL;
    m_out = NULL;
}

void TPMCommand::buildCmdPacket(TSS2_SYS_CONTEXT *ctx) {
}

void TPMCommand::unpackRspPacket(TSS2_SYS_CONTEXT *ctx) {
}

TPMCommand::~TPMCommand() {
}

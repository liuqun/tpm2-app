//**********************************************************************;
// Copyright (c) 2015, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;

#ifndef TCTI_SOCKET_H
#define TCTI_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sapi/tpm20.h>
#include <tcti/common.h>

#define DEFAULT_SIMULATOR_TPM_PORT        2321
#define TSS2_SIMULATOR_INTERFACE_INIT_FAILED              ((TSS2_RC)(1 + TSS2_DRIVER_ERROR_LEVEL))

#define DEFAULT_RESMGR_TPM_PORT        2323
#define TSS2_RESMGR_INTERFACE_INIT_FAILED                 ((TSS2_RC)(1 + TSS2_TCTI_ERROR_LEVEL))

#define DEFAULT_HOSTNAME        "127.0.0.1"

/* global data defined in the socket TCTI */
extern int (*printfFunction)( printf_type type, const char *format, ...);

TSS2_RC PlatformCommand(
    TSS2_TCTI_CONTEXT *tctiContext,     /* in */
    char cmd );

typedef struct {
    const char *hostname;
    uint16_t port;
    TCTI_LOG_CALLBACK logCallback;
    TCTI_LOG_BUFFER_CALLBACK logBufferCallback;
    void *logData;
} TCTI_SOCKET_CONF;

TSS2_RC InitSocketTcti (
    TSS2_TCTI_CONTEXT *tctiContext, // OUT
    size_t *contextSize,            // IN/OUT
    const TCTI_SOCKET_CONF *config,             // IN
    const uint8_t serverSockets
    );

TSS2_RC SendSessionEndSocketTcti(
    TSS2_TCTI_CONTEXT *tctiContext,
    UINT8 tpmCmdServer
    );

// Commands to send to OTHER port.
#define MS_SIM_POWER_ON         1
#define MS_SIM_POWER_OFF        2
#define MS_SIM_TPM_SEND_COMMAND 8
#define MS_SIM_CANCEL_ON        9
#define MS_SIM_CANCEL_OFF       10
#define MS_SIM_NV_ON            11
#define TPM_SESSION_END         20

#ifdef __cplusplus
}
#endif

#endif /* TCTI_SOCKET_H */

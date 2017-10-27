// Encoding: UTF-8 (Please set your editor with UTF-8 encoding if the Chinese characters are unreadable)

#include <stdlib.h>
#include "tcti-detector.h"
#include <sapi/tpm20.h>

int main(int argc, char *argv[])
{
    int ret;
    tcti_detector_t detector;

    ret = EXIT_FAILURE;
    detector = new_tcti_detector();
    if (tcti_detector_auto_probe(detector) == PROBE_SUCCESS) {
        ret = EXIT_SUCCESS;
        TSS2_SYS_CONTEXT *sysContext;
        size_t sysContextSize;

        sysContextSize = Tss2_Sys_GetContextSize(0);
        sysContext = (TSS2_SYS_CONTEXT *) malloc(sysContextSize);
        TSS2_ABI_VERSION ver;
        ver.tssCreator = TSSWG_INTEROP;
        ver.tssFamily  = TSS_SAPI_FIRST_FAMILY;
        ver.tssLevel   = TSS_SAPI_FIRST_LEVEL;
        ver.tssVersion = TSS_SAPI_FIRST_VERSION;
        TSS2_RC rc;
        rc = Tss2_Sys_Initialize(sysContext, sysContextSize, tcti_detector_get_tcti_context(detector), &ver);
        Tss2_Sys_Finalize(sysContext);
        free(sysContext);
    }
    delete_tcti_detector(detector);
    return (ret);
}

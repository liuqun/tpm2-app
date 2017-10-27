/* (Using UTF-8 encoding for Chinese characters) */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#ifndef TCTI_DETECTOR_H_
#define TCTI_DETECTOR_H_

#include "config.h"
#include "probe.h"
#include <sapi/tpm20.h>

typedef union {
    void *ptr;
    struct probe_instance_t *probe;
    struct tcti_detector_instance_t *self;
} tcti_detector_t;

#ifdef __cplusplus
extern "C" {
#endif

tcti_detector_t new_tcti_detector();
void delete_tcti_detector(tcti_detector_t detector);
probe_result_t tcti_detector_auto_probe(tcti_detector_t detector);
const char *tcti_detector_get_current_loaded_library_pathname(const tcti_detector_t detector);
TSS2_TCTI_CONTEXT *tcti_detector_get_tcti_context(tcti_detector_t detector);

#ifdef __cplusplus
}; /* end of extern "C" */
#endif

#endif /* TCTI_DETECTOR_H_ */

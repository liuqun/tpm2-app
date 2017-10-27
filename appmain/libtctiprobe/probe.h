/* (Using UTF-8 encoding for Chinese characters) */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#ifndef PROBE_H_
#define PROBE_H_

#include "config.h"

typedef enum {
    PROBE_SUCCESS=0,
    PROBE_GENERIC_FAILURE,
} probe_result_t;

typedef struct probe_instance_t *probe_t;

#ifdef __cplusplus
extern "C" {
#endif

probe_t new_probe_instance();
void delete_probe_instance(probe_t probe);
probe_result_t load_library(probe_t probe, const char *lib);
const char *get_current_loaded_library_pathname(const probe_t probe);

#ifdef __cplusplus
}; /* end of extern "C" */
#endif

#endif /* PROBE_H_ */

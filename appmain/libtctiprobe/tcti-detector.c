/* (Using UTF-8 encoding for Chinese characters) */

/* Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <dlfcn.h>
#include "tcti-detector.h"

#if defined(FEATURE_TCTI_PROBE_ENABLED)

/* K&R 代码风格: 使用 4 个空格, 不使用 Tab */

typedef void (*instance_cleanup_func_t)(void *instance);

struct probe_instance_t {
    void *handle;
    char *from_which_lib;
    instance_cleanup_func_t cleanup;
};

static void dummy_instance_cleanup(void *instance)
{
    (void) instance; /* gcc -Wunused-parameter */
}

static void probe_instance_init(struct probe_instance_t *instance)
{
    instance->handle = NULL;
    instance->from_which_lib = NULL;
    instance->cleanup = dummy_instance_cleanup;
}

static void probe_instance_cleanup(void *instance)
{
    probe_t probe;

    probe = instance;
    if (probe->handle) {
        dlclose(probe->handle);
        probe->handle = NULL;
    }
    if (probe->from_which_lib) {
        free(probe->from_which_lib);
        probe->from_which_lib = NULL;
    }
    probe->cleanup = dummy_instance_cleanup;
}


#include <string.h>

#ifndef __USE_XOPEN2K8
static char *strndup(const char *s, size_t n)
{
    char *dst;
    char *compact;
    int i;

    dst = malloc(n + 1);

    for (i = 0; i < n && *s; i++, s++) {
        dst[i] = *s;
    }
    dst[i] = '\0';
    if (i < n && (compact = realloc(dst, i + 1))) {
        dst = compact;
    }
    return dst;
}
#endif /* __USE_XOPEN2K8 */

probe_result_t load_library(probe_t self, const char *lib)
{
    void *handle;

    assert(self);
    self->cleanup(self);

    handle = NULL;
    handle = dlopen(lib, RTLD_NOW);
    if (!handle) {
        int rc = errno;
        fprintf(stderr, "Failed to open dll library: %s: rc=0x%X\n", dlerror(), rc);
        return PROBE_GENERIC_FAILURE;
    }

    self->handle = handle;
    const int MAX_BYTES = /* Hard-coded max filepath length: */ 1024;
    self->from_which_lib = strndup(lib, MAX_BYTES);
    self->cleanup = probe_instance_cleanup;
    return (PROBE_SUCCESS);
}

const char *get_current_loaded_library_pathname(const probe_t self)
{
    if (!self || !self->from_which_lib) {
        return ("");
    }
    return (self->from_which_lib);
}

#include <tcti/tcti_device.h>
#include <tcti/tcti-tabrmd.h>

typedef TSS2_RC (*init_device_tcti_func_t)(
    TSS2_TCTI_CONTEXT *,
    size_t *,
    const TCTI_DEVICE_CONF *
);

typedef TSS2_RC (*init_tabrmd_tcti_func_t)(
    TSS2_TCTI_CONTEXT *,
    size_t *
);

struct tcti_detector_instance_t {
    struct probe_instance_t probe;
    instance_cleanup_func_t cleanup;
    size_t tcti_context_size;
    void *tcti_context;
    struct {
        init_device_tcti_func_t InitDeviceTcti;
        init_tabrmd_tcti_func_t tss2_tcti_tabrmd_init;
    } tcti_func_list;
};

static void tcti_detector_cleanup(void *instance)
{
    tcti_detector_t detector;

    detector.ptr = instance;

    /* 1. Clean up sub items. */
    detector.probe->cleanup(instance);
    /* 2. Release allocated memory space. */
    if (detector.self->tcti_context_size > 0 && detector.self->tcti_context) {
        free(detector.self->tcti_context);
    }
    detector.self->tcti_context_size = 0;
    detector.self->tcti_context = NULL;
    detector.self->tcti_func_list.InitDeviceTcti = ((init_device_tcti_func_t) NULL);
    detector.self->tcti_func_list.tss2_tcti_tabrmd_init = ((init_tabrmd_tcti_func_t) NULL);
    /* 3. Relink clean-up function pointer to the dummy one. */
    detector.self->cleanup = dummy_instance_cleanup;
}

const char *tcti_detector_get_current_loaded_library_pathname(const tcti_detector_t detector)
{
    return (get_current_loaded_library_pathname(detector.probe));
}

static void tcti_detector_init(struct tcti_detector_instance_t *instance)
{
    assert(instance);

    probe_instance_init(&(instance->probe));
    instance->cleanup = dummy_instance_cleanup;
    instance->tcti_context_size = 0;
    instance->tcti_context = NULL;
    instance->tcti_func_list.InitDeviceTcti = ((init_device_tcti_func_t) NULL);
    instance->tcti_func_list.tss2_tcti_tabrmd_init = ((init_tabrmd_tcti_func_t) NULL);
}

tcti_detector_t new_tcti_detector()
{
    struct tcti_detector_instance_t *instance;

    instance = malloc(sizeof(struct tcti_detector_instance_t));
    assert(instance);
    tcti_detector_init(instance);
    return ((tcti_detector_t) instance);
}

void delete_tcti_detector(tcti_detector_t instance)
{
    if (!instance.ptr) {
        return;
    }
    instance.self->cleanup(instance.ptr);
    free(instance.self);
}

#ifdef STATIC_LINKING_AGAINST_TCTI_DEVICE_LIB_IS_ALLOWED
static init_device_tcti_func_t InitDeviceTcti_static = InitDeviceTcti;
#else
static init_device_tcti_func_t InitDeviceTcti_static = ((init_device_tcti_func_t) NULL);
#endif

static
probe_result_t probe_device_tcti(struct tcti_detector_instance_t *self)
{
    probe_result_t probe_err;
    struct probe_instance_t probe;
    probe_result_t ret;

    ret = PROBE_GENERIC_FAILURE;

    assert(self);
    if (!self) {
        return (PROBE_GENERIC_FAILURE);
    }

    probe_instance_init(&probe);
    self->tcti_func_list.InitDeviceTcti = ((init_device_tcti_func_t) NULL);
    probe_err = load_library(&probe, "libtcti-device.so");
    if (!probe_err) {
        self->tcti_func_list.InitDeviceTcti = dlsym(probe.handle, "InitDeviceTcti");
    }
    if (!self->tcti_func_list.InitDeviceTcti) {
        /* Fallback to static link against shared lib "libtiti-device.so" (or "libtcti-device.a"). */
        self->tcti_func_list.InitDeviceTcti = InitDeviceTcti_static;
        probe_instance_cleanup(&probe);
    }
    if (self->tcti_func_list.InitDeviceTcti) {
        TCTI_DEVICE_CONF linux_kernel_space_tpm_resource_manager = {"/dev/tpmrm0", NULL, NULL};
        TCTI_DEVICE_CONF linux_tpm_device_driver = {"/dev/tpm0", NULL, NULL};
        TCTI_DEVICE_CONF *list[] = {
            &linux_kernel_space_tpm_resource_manager,
            &linux_tpm_device_driver,
            NULL,
        };
        int i;

        for (i = 0; list[i]; i++) {
            size_t min;
            size_t n;
            TCTI_DEVICE_CONF *conf;
            int err;
            TSS2_TCTI_CONTEXT *tcti_context;
            size_t tcti_context_size;

            min = sizeof(TSS2_TCTI_CONTEXT_COMMON_V1);
            n = 0;
            err = self->tcti_func_list.InitDeviceTcti(NULL, &n, NULL);
            if (err || n < min) {
                continue;
            }
            tcti_context_size = n;

            tcti_context = malloc(tcti_context_size);
            conf = list[i];
            err = self->tcti_func_list.InitDeviceTcti(tcti_context, &n, conf);
            if (err) {
                free(tcti_context);
                continue;
            }
            self->tcti_context = tcti_context;
            self->tcti_context_size = tcti_context_size;
            memcpy(&self->probe, &probe, sizeof(struct probe_instance_t));
            self->cleanup = tcti_detector_cleanup;
            return (PROBE_SUCCESS);
        }
        if (!list[i])
        {
            // Warning: 之前若干次尝试创建TCTI Device上下文均失败
            ret = PROBE_GENERIC_FAILURE;
            probe_instance_cleanup(&probe);
        }
    }
    return (ret);
}

#ifdef STATIC_LINKING_AGAINST_TCTI_TABRMD_LIB_IS_ALLOWED
static init_tabrmd_tcti_func_t tss2_tcti_tabrmd_init_static = tss2_tcti_tabrmd_init;
#else
static init_tabrmd_tcti_func_t tss2_tcti_tabrmd_init_static = ((init_tabrmd_tcti_func_t) NULL);
#endif

static
probe_result_t probe_tabrmd_tcti(struct tcti_detector_instance_t *self)
{
    size_t min;
    size_t n;
    int err;
    TSS2_TCTI_CONTEXT *tcti_context;
    size_t tcti_context_size;
    probe_result_t probe_err;
    struct probe_instance_t probe;

    assert(self);
    if (!self) {
        return (PROBE_GENERIC_FAILURE);
    }

    probe_instance_init(&probe);
    self->tcti_func_list.tss2_tcti_tabrmd_init = ((init_tabrmd_tcti_func_t) NULL);
    probe_err = load_library(&probe, "libtcti-tabrmd.so");
    if (!probe_err) {
        self->tcti_func_list.tss2_tcti_tabrmd_init = dlsym(probe.handle, "tss2_tcti_tabrmd_init");
    }
    if (!self->tcti_func_list.tss2_tcti_tabrmd_init) {
        /* Fallback to static link against shared lib "libtiti-tabrmd.so" (or "libtcti-tabrmd.a"). */
        self->tcti_func_list.tss2_tcti_tabrmd_init = tss2_tcti_tabrmd_init_static;
        probe_instance_cleanup(&probe);
    }
    if (!self->tcti_func_list.tss2_tcti_tabrmd_init) {
        return (PROBE_GENERIC_FAILURE);
    }

    min = sizeof(TSS2_TCTI_CONTEXT_COMMON_V1);
    n = 0;
    err = self->tcti_func_list.tss2_tcti_tabrmd_init(NULL, &n);
    if (err || n < min) {
        probe_instance_cleanup(&probe);
        return (PROBE_GENERIC_FAILURE);
    }
    tcti_context_size = n;

    tcti_context = malloc(tcti_context_size);
    err = self->tcti_func_list.tss2_tcti_tabrmd_init(tcti_context, &n);
    if (err) {
        free(tcti_context);
        probe_instance_cleanup(&probe);
        return (PROBE_GENERIC_FAILURE);
    }
    self->tcti_context = tcti_context;
    self->tcti_context_size = tcti_context_size;
    memcpy(&self->probe, &probe, sizeof(struct probe_instance_t));
    self->cleanup = tcti_detector_cleanup;
    return (PROBE_SUCCESS);
}

probe_result_t tcti_detector_auto_probe(tcti_detector_t detector)
{
    struct tcti_detector_instance_t *self;
    probe_result_t ret;

    ret = PROBE_GENERIC_FAILURE;
    assert(detector.ptr);
    if (!detector.ptr) {
        return (PROBE_GENERIC_FAILURE);
    }

    tcti_detector_cleanup(detector.ptr);

    if (PROBE_SUCCESS == (ret = probe_device_tcti(detector.self))) {
        return (PROBE_SUCCESS);
    }

    if (PROBE_SUCCESS == (ret = probe_tabrmd_tcti(detector.self))) {
        return (PROBE_SUCCESS);
    }

    return ret;
}

TSS2_TCTI_CONTEXT *tcti_detector_get_tcti_context(tcti_detector_t detector)
{
    return (detector.self->tcti_context);
}

#endif /* defined(FEATURE_TCTI_PROBE_ENABLED) */

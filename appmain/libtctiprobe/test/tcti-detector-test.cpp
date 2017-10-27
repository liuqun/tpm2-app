// Encoding: UTF-8 (Please set your editor with UTF-8 encoding if the Chinese characters are unreadable)

#include <stdlib.h>
#include "tcti-detector.h"
#include <sapi/tpm20.h>
#include "connection-manager.h"
#include <string>


class MyConnectionManager: public ConnectionManager {
public:
    /// 构造函数
    MyConnectionManager();
    /// 析构函数
    ~MyConnectionManager();
    /// 依次尝试连接到设备文件 /dev/tpmrm0, /dev/tpm0, 以及 tpm2-abrmd DBus 守护进程
    void connect();
    /// 主动断开连接
    void disconnect();
    /// 回调函数, 在已经建立的 TCTI 链路层基础上创建 system level API 上下文
    void initializeSysContext(TSS2_SYS_CONTEXT *sys_context, size_t sys_context_size);

private:
    tcti_detector_t m_detector;
};


MyConnectionManager::MyConnectionManager()
{
    m_detector = new_tcti_detector();
}

MyConnectionManager::~MyConnectionManager()
{
    delete_tcti_detector(m_detector);
}

void MyConnectionManager::connect()
{
    int probe_status;
    probe_status = tcti_detector_auto_probe(m_detector);
    if (PROBE_SUCCESS != probe_status) {
        throw ConnectionManagerError(
                "TPM2.0 device /dev/tpm0 is not accessable, and tpm2-abrmd service is not accessable either"
            );
    }
}

static void CloseTCTIConnection(TSS2_TCTI_CONTEXT *tcti_context)
{
    TSS2_TCTI_CONTEXT_COMMON_CURRENT *p;

#ifdef tss2_tcti_finalize
    tss2_tcti_finalize(tcti_context);
    return;
#endif

    p = (TSS2_TCTI_CONTEXT_COMMON_CURRENT *) tcti_context;
    if (p && p->version >= 1 && p->finalize) {
        p->finalize(tcti_context);
    }
    return;
}

void MyConnectionManager::disconnect()
{
    TSS2_TCTI_CONTEXT *tcti_context;

    /* Close /dev/tpm0 fd, socket fd or DBus connection */
    tcti_context = tcti_detector_get_tcti_context(m_detector);
    if (!tcti_context) {
        throw ConnectionManagerError(
                "TCTI is not connected yet!"
            );
    }
    CloseTCTIConnection(tcti_context);
}

void MyConnectionManager::initializeSysContext(TSS2_SYS_CONTEXT *sys_context, size_t sys_context_size)
{
    TSS2_TCTI_CONTEXT *tcti_context;
    TSS2_ABI_VERSION ver;
    ver.tssCreator = TSSWG_INTEROP;
    ver.tssFamily = TSS_SAPI_FIRST_FAMILY;
    ver.tssLevel = TSS_SAPI_FIRST_LEVEL;
    ver.tssVersion = TSS_SAPI_FIRST_VERSION;

    TSS2_RC err;

    tcti_context = tcti_detector_get_tcti_context(m_detector);
    if (!tcti_context) {
        throw ConnectionManagerError(
            "TCTI is not connected yet!"
        );
    }

    err = 0;
    err = Tss2_Sys_Initialize(
            sys_context,
            sys_context_size,
            tcti_context,
            &ver);
    if (err) {
        throw ConnectionManagerError(
                "TPM 2.0 Software Stack System API Initialization failed!"
            );
    }
}

ConnectionManagerError::ConnectionManagerError(const std::string &msg): std::runtime_error(msg)
{
}

#include <stdio.h>

int main(int argc, char *argv[])
{
    int ret;
    tcti_detector_t detector;
    MyConnectionManager manager;
    TSS2_SYS_CONTEXT *sys_context;
    size_t sys_context_size;

    ret = EXIT_FAILURE;
    try {
        manager.connect();
        sys_context_size = Tss2_Sys_GetContextSize(0);
        sys_context = (TSS2_SYS_CONTEXT *) malloc(sys_context_size);
        if (sys_context) {
            manager.initializeSysContext(sys_context, sys_context_size);
            // TODO: Do some test with the sys_context here
            Tss2_Sys_Finalize(sys_context);
            free(sys_context);
        }
        manager.disconnect();
        ret = EXIT_SUCCESS;
    } catch (const std::exception &e) {
        fprintf(stderr, "%s\n", e.what());
    }

    return (ret);
}

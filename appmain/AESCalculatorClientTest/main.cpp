/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <cstdio>
#include <cstdlib>
using namespace std;

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#ifndef DEFAULT_RESMGR_TPM_PORT /* @note This mircro and the legacy resourcemgr has been removed by upstream developer since 2017-05-09. @see https://github.com/01org/TPM2.0-TSS/commit/7966ef8916f79ed09eab966a58d773f413fbb67f#diff-9b5d40e51314bbf4fdfc0997a4b58838L41 */
    #warning // DEFAULT_RESMGR_TPM_PORT was removed from <tcti_socket.h>!
    #warning // You should either use "tcti/tcti-tabrmd.h" (which is a replacement to the legacy resourcemgr), or directly connect to port 2321 of the simulator without a resourcemgr!
    #warning // See https://github.com/01org/tpm2-abrmd
    #include <stdint.h>
    const uint16_t DEFAULT_RESMGR_TPM_PORT=DEFAULT_SIMULATOR_TPM_PORT;
#endif
#include "TPMCommand.h"
#include "Client.h"
#include "CalculatorClient.h"

/* 排版格式: 以下函数均使用4个空格缩进，不使用Tab缩进 */

static void PrintHelp()
{
    printf("用法:\n");
    printf("-rmhost 手动指定运行资源管理器(即 resourcemgr)的主机IP地址或主机名 (默认值: %s)\n",
            DEFAULT_HOSTNAME);
    printf("-rmport 手动指定运行资源管理器的主机端口号 (默认值: %d)\n", DEFAULT_RESMGR_TPM_PORT);
    printf("-localTctiTest\n");
    printf("[注意: 若使用 -localTctiTest 请手动关闭任何占用/dev/tpm0设备的进程, 即: 关闭其他直接访问/dev/tpm0的resourcemgr进程]\n");
}

#include <vector>
using std::vector;
#include <string>
using std::string;
#include <sstream>
using std::ostringstream;
#include <stdexcept>
using std::exception;
using std::runtime_error;

int main(int argc, char *argv[])
{
    int count;
    int usingDeviceFile = false;
    const char *deviceFile = "/dev/tpm0";
    const char *hostname = "127.0.0.1";
    uint16_t port = DEFAULT_RESMGR_TPM_PORT;

    count = 1;
    while (count < argc)
    {
        if( 0 == strcmp(argv[count], "-localTctiTest" ) )
        {
            usingDeviceFile = true;
            count += 1;
            // 以上代码提供的命令行参数为: -localTctiTest
            // 用于直接操作/dev/tpm0设备
            continue;
        }

        if (0 == strcmp(argv[count], "-rmhost"))
        {
            if (count + 1 >= argc)
            {
                PrintHelp();
                return 1;
            }
            hostname = argv[count + 1];  // 暂时不检查无效的输入参数
            count += 2;
        }
        else if (0 == strcmp(argv[count], "-rmport"))
        {
            if (count + 1 >= argc)
            {
                PrintHelp();
                return 1;
            }
            port = strtoul(argv[count + 1], NULL, 10); // 暂时不检查无效的输入参数
            count += 2;
        }
        else
        {
            PrintHelp();
            return -1;
        }
        // 以上代码提供了一组简单的命令行参数便于调试:
        // 其中包括 [-rmhost IP地址] 和 [-rmport 端口号]
        // 如果不指定命令行参数, 则会直接连接到本机 IP 地址默认端口上运行的资源管理器
    }

    SocketBasedTSSContextInitializer socketTCTIContextInitializer(hostname, port);
    DeviceBasedTSSContextInitializer deviceTCTIContextInitializer(deviceFile);

    TSSContextInitializer *pInitializer; ///< 通过指针选择使用哪一个上下文初始化器

    pInitializer = &socketTCTIContextInitializer;
    if (usingDeviceFile)
    {
        pInitializer = &deviceTCTIContextInitializer;
    }

    class AESCalculatorClient: public Client
    {
    public:
        vector<unsigned char> m_decryptedDataOut;
        vector<unsigned char> m_encryptedDataOut;
    public:
        ~AESCalculatorClient() {
            m_encryptedDataOut.clear();
            // 抹除解密后的敏感内容
            vector<unsigned char>::iterator i;
            for (i=m_decryptedDataOut.begin(); i!=m_decryptedDataOut.end(); i++)
            {
                *i = (unsigned char) 0xFF;
            }
        }
    public:
        const std::vector<BYTE>& encryptSingleBlock(
                const void *data, // 输入参数: 指向输入数据的指针
                unsigned short nDatalength, // 数据长度. 单位: 字节. 单条输入数据的长度上限受TSS和物理硬件共同限制, 实际上限有可能小于1024字节
                const void *key, // AES密钥值
                unsigned short nKeyLength // 密钥长度. 单位: 字节.
                )
        {
            int MAX_INPUT_DATA_LENGTH_IN_BYTES = sizeof(TPM2B_MAX_BUFFER) - 2;

            if (nDatalength > MAX_INPUT_DATA_LENGTH_IN_BYTES)
            {
                std::ostringstream msg;
                msg << "Error: 单个输入数据包最大长度不能超过" << MAX_INPUT_DATA_LENGTH_IN_BYTES << "字节";
                throw std::runtime_error(msg.str());
            }
            // 检查密钥长度
            //int MAX_KEY_LENGTH_IN_BYTES = 128;
            //if (nKeyLength > MAX_KEY_LENGTH_IN_BYTES)
            //{
            //    nKeyLength = MAX_KEY_LENGTH_IN_BYTES;
            //}

            m_encryptedDataOut.clear();

            try {
                TPMI_RH_HIERARCHY hierarchy = TPM_RH_NULL; // 在 TPM_RH_NULL 区域创建的节点是临时节点
                const char *ExternalKeyPassword = "";
                const UINT16 ExternalKeyPasswordLen = strlen(ExternalKeyPassword);
                TPMCommands::LoadExternal loadextn;
                printf("设置 LoadExternal 命令帧参数\n");
                loadextn.configHierarchy(hierarchy);
                loadextn.configSensitiveDataBits(key, nKeyLength);
                loadextn.configKeyTypeSymmetricAES128CFB();
                loadextn.configKeyAuthValue(ExternalKeyPassword, ExternalKeyPasswordLen);
                printf("发送 LoadExternal 命令桢创建临时节点(用于存储用户输入的自定义对称密钥)\n");
                sendCommand(loadextn);
                fetchResponse();
                {
                    char buf[nKeyLength];
                    memset(buf, 0xFF, nKeyLength);
                    loadextn.configSensitiveDataBits(buf, nKeyLength); // 手动覆盖清除之前缓存的对称密钥值副本(属于敏感数据)
                }
                printf("临时节点创建成功, 密钥句柄=0x%08X\n", (int)loadextn.outObjectHandle());

                {
                    TPM_HANDLE loadedSymKeyHandle = loadextn.outObjectHandle();
                    printf("调用单条 Tss2_Sys_EncryptDecrypt 或 Tss2_Sys_EncryptDecrypt2 命令进行加密\n");
                    try
                    {
                        TPM2B_IV ivIn;
                        TPM2B_MAX_BUFFER dataIn;
                        TPM2B_MAX_BUFFER dataOut;
                        TPM2B_IV ivOut;
                        dataIn.t.size = nDatalength;
                        memcpy(dataIn.t.buffer, data, nDatalength);
                        dataOut.t.size = sizeof(dataOut) - sizeof(dataOut.t.size);
                        ivIn.t.size = MAX_SYM_BLOCK_SIZE;
                        memset(ivIn.t.buffer, 0x00, ivIn.t.size);
                        ivOut.t.size = sizeof(ivOut) - sizeof(ivOut.t.size);

                        /* 输入参数 TSS2_SYS_CMD_AUTHS */
                        TPMS_AUTH_COMMAND cmdAuth;
                        TPMS_AUTH_COMMAND *cmdAuths[3];

                        cmdAuth.sessionHandle = TPM_RS_PW;
                        memset(&(cmdAuth.sessionAttributes), 0x00, sizeof(cmdAuth.sessionAttributes));
                        cmdAuth.nonce.t.size = 0;
                        cmdAuth.hmac.t.size = ExternalKeyPasswordLen;
                        if (ExternalKeyPasswordLen)
                        {
                            memcpy(cmdAuth.hmac.t.buffer, ExternalKeyPassword, ExternalKeyPasswordLen);
                        }
                        cmdAuths[0] = &cmdAuth;

                        TSS2_SYS_CMD_AUTHS cmdAuthsArray;
                        cmdAuthsArray.cmdAuthsCount = 1;
                        cmdAuthsArray.cmdAuths = cmdAuths;

                        /* 输出参数 TSS2_SYS_RSP_AUTHS */
                        TPMS_AUTH_RESPONSE rspAuth;
                        TPMS_AUTH_RESPONSE *rspAuths[3];

                        memset(&rspAuth, 0x00, sizeof(rspAuth));
                        rspAuths[0] = &rspAuth;

                        TSS2_SYS_RSP_AUTHS rspAuthsArray;
                        rspAuthsArray.rspAuthsCount = 1;
                        rspAuthsArray.rspAuths = rspAuths;

                        /* TODO: Use Tss2_Sys_EncryptDecrypt2() to replace the deprecated Tss2_Sys_EncryptDecrypt() */
                        TSS2_RC rc = Tss2_Sys_EncryptDecrypt(
                                m_sysContext,
                                loadedSymKeyHandle,
                                &cmdAuthsArray,
                                0/* 0:Encrypt; 1:Decrypt */,
                                TPM_ALG_CFB,
                                &ivIn, &dataIn, &dataOut, &ivOut,
                                &rspAuthsArray);
                        if (rc != TSS2_RC_SUCCESS)
                        {
                            printf("TPM命令执行失败!\n");
                            throw rc;
                        }
                        m_encryptedDataOut.assign(dataOut.t.buffer, dataOut.t.buffer+dataOut.t.size);
                        printf("加密成功\n");
                    }
                    catch (TSS2_RC rc)
                    {
                        printf("Tss2_Sys_EncryptDecrypt() returned an error code 0x%X\n", rc);
                    }
                    catch (...)
                    {
                        printf("Other Unknown error happened in TPM command Tss2_Sys_EncryptDecrypt()\n");
                    }
                }

                printf("调用 Flush 命令清理临时节点\n");
                TPMCommands::FlushLoadedKeyNode flush;
                TPM_HANDLE h = loadextn.outObjectHandle();
                if ((TPM_RH_NULL == hierarchy) && (h & 0xFF000000) != 0x80000000) {
                    std::ostringstream msg;
                    msg << "Unexpected TPM HANDLE h=0x" << std::hex << (int)h << ", under hierarchy=0x" << (int)hierarchy;
                    throw std::runtime_error(msg.str());
                }
                flush.configKeyNodeToFlushAway(h);
                printf("发送 FlushContext 命令桢, 让 TPM 删除之前 LoadExternal 命令加载的节点\n");
                sendCommand(flush);
                fetchResponse();
                printf("节点删除完毕\n");
            } catch (TSS2_RC rc) {
                std::ostringstream msg;
                msg << "TPM Command LoadExternal() has returned an error code 0x" << std::hex << rc;
                throw std::runtime_error(msg.str());
            } catch (std::exception& e) {
                std::ostringstream msg;
                msg << "TPM Command FlushContext(): An error happened: " << e.what();
                throw std::runtime_error(msg.str());
            } catch (...) {
                throw std::runtime_error("Unknown error happened in TPM command LoadExternal() or FlushContext()");
            }

            /* 返回密文 */
            return (m_encryptedDataOut);
        }

    public:
        const std::vector<BYTE>& decryptSingleBlock(
                const void *data, // 输入参数: 指向输入数据的指针
                unsigned short nDatalength, // 数据长度. 单位: 字节. 单条输入数据的长度上限受TSS和物理硬件共同限制, 实际上限有可能小于1024字节
                const void *key, // AES密钥值
                unsigned short nKeyLength // 密钥长度. 单位: 字节.
                )
        {
            int MAX_INPUT_DATA_LENGTH_IN_BYTES = sizeof(TPM2B_MAX_BUFFER) - 2;

            if (nDatalength > MAX_INPUT_DATA_LENGTH_IN_BYTES)
            {
                std::ostringstream msg;
                msg << "Error: 单个输入数据包最大长度不能超过" << MAX_INPUT_DATA_LENGTH_IN_BYTES << "字节";
                throw std::runtime_error(msg.str());
            }
            // 检查密钥长度
            //int MAX_KEY_LENGTH_IN_BYTES = 128;
            //if (nKeyLength > MAX_KEY_LENGTH_IN_BYTES)
            //{
            //    nKeyLength = MAX_KEY_LENGTH_IN_BYTES;
            //}

            m_encryptedDataOut.clear();

            try {
                TPMI_RH_HIERARCHY hierarchy = TPM_RH_NULL; // 在 TPM_RH_NULL 区域创建的节点是临时节点
                const char *ExternalKeyPassword = "";
                const UINT16 ExternalKeyPasswordLen = strlen(ExternalKeyPassword);
                TPMCommands::LoadExternal loadextn;
                printf("设置 LoadExternal 命令帧参数\n");
                loadextn.configHierarchy(hierarchy);
                loadextn.configSensitiveDataBits(key, nKeyLength);
                loadextn.configKeyTypeSymmetricAES128CFB();
                loadextn.configKeyAuthValue(ExternalKeyPassword, ExternalKeyPasswordLen);
                printf("发送 LoadExternal 命令桢创建临时节点(用于存储用户输入的自定义对称密钥)\n");
                sendCommand(loadextn);
                fetchResponse();
                {
                    char buf[nKeyLength];
                    memset(buf, 0xFF, nKeyLength);
                    loadextn.configSensitiveDataBits(buf, nKeyLength); // 手动覆盖清除之前缓存的对称密钥值副本(属于敏感数据)
                }
                printf("临时节点创建成功, 密钥句柄=0x%08X\n", (int)loadextn.outObjectHandle());

                {
                    TPM_HANDLE loadedSymKeyHandle = loadextn.outObjectHandle();
                    printf("调用单条 Tss2_Sys_EncryptDecrypt 或 Tss2_Sys_EncryptDecrypt2 命令进行解密...\n");
                    try
                    {
                        TPM2B_IV ivIn;
                        TPM2B_MAX_BUFFER dataIn;
                        TPM2B_MAX_BUFFER dataOut;
                        TPM2B_IV ivOut;
                        dataIn.t.size = nDatalength;
                        memcpy(dataIn.t.buffer, data, nDatalength);
                        dataOut.t.size = sizeof(dataOut) - sizeof(dataOut.t.size);
                        ivIn.t.size = MAX_SYM_BLOCK_SIZE;
                        memset(ivIn.t.buffer, 0x00, ivIn.t.size);
                        ivOut.t.size = sizeof(ivOut) - sizeof(ivOut.t.size);

                        /* 输入参数 TSS2_SYS_CMD_AUTHS */
                        TPMS_AUTH_COMMAND cmdAuth;
                        TPMS_AUTH_COMMAND *cmdAuths[3];

                        cmdAuth.sessionHandle = TPM_RS_PW;
                        memset(&(cmdAuth.sessionAttributes), 0x00, sizeof(cmdAuth.sessionAttributes));
                        cmdAuth.nonce.t.size = 0;
                        cmdAuth.hmac.t.size = ExternalKeyPasswordLen;
                        if (ExternalKeyPasswordLen)
                        {
                            memcpy(cmdAuth.hmac.t.buffer, ExternalKeyPassword, ExternalKeyPasswordLen);
                        }
                        cmdAuths[0] = &cmdAuth;

                        TSS2_SYS_CMD_AUTHS cmdAuthsArray;
                        cmdAuthsArray.cmdAuthsCount = 1;
                        cmdAuthsArray.cmdAuths = cmdAuths;

                        /* 输出参数 TSS2_SYS_RSP_AUTHS */
                        TPMS_AUTH_RESPONSE rspAuth;
                        TPMS_AUTH_RESPONSE *rspAuths[3];

                        memset(&rspAuth, 0x00, sizeof(rspAuth));
                        rspAuths[0] = &rspAuth;

                        TSS2_SYS_RSP_AUTHS rspAuthsArray;
                        rspAuthsArray.rspAuthsCount = 1;
                        rspAuthsArray.rspAuths = rspAuths;

                        /* TODO: Use Tss2_Sys_EncryptDecrypt2() to replace the deprecated Tss2_Sys_EncryptDecrypt() */
                        TSS2_RC rc = Tss2_Sys_EncryptDecrypt(
                                m_sysContext,
                                loadedSymKeyHandle,
                                &cmdAuthsArray,
                                1/* 0:Encrypt; 1:Decrypt */,
                                TPM_ALG_CFB,
                                &ivIn, &dataIn, &dataOut, &ivOut,
                                &rspAuthsArray);
                        if (rc != TSS2_RC_SUCCESS)
                        {
                            printf("TPM命令执行失败!\n");
                            throw rc;
                        }
                        m_decryptedDataOut.assign(dataOut.t.buffer, dataOut.t.buffer+dataOut.t.size);
                        printf("解密成功\n");
                    }
                    catch (TSS2_RC rc)
                    {
                        printf("Tss2_Sys_EncryptDecrypt() returned an error code 0x%X\n", rc);
                    }
                    catch (...)
                    {
                        printf("Other Unknown error happened in TPM command Tss2_Sys_EncryptDecrypt()\n");
                    }
                }

                printf("调用 Flush 命令清理临时节点\n");
                TPMCommands::FlushLoadedKeyNode flush;
                TPM_HANDLE h = loadextn.outObjectHandle();
                if ((TPM_RH_NULL == hierarchy) && (h & 0xFF000000) != 0x80000000) {
                    std::ostringstream msg;
                    msg << "Unexpected TPM HANDLE h=0x" << std::hex << (int)h << ", under hierarchy=0x" << (int)hierarchy;
                    throw std::runtime_error(msg.str());
                }
                flush.configKeyNodeToFlushAway(h);
                printf("发送 FlushContext 命令桢, 让 TPM 删除之前 LoadExternal 命令加载的节点\n");
                sendCommand(flush);
                fetchResponse();
                printf("节点删除完毕\n");
            } catch (TSS2_RC rc) {
                std::ostringstream msg;
                msg << "TPM Command LoadExternal() has returned an error code 0x" << std::hex << rc;
                throw std::runtime_error(msg.str());
            } catch (std::exception& e) {
                std::ostringstream msg;
                msg << "TPM Command FlushContext(): An error happened: " << e.what();
                throw std::runtime_error(msg.str());
            } catch (...) {
                throw std::runtime_error("Unknown error happened in TPM command LoadExternal() or FlushContext()");
            }

            /* 返回明文 */
            return (m_decryptedDataOut);
        }
    };

    pInitializer->connect();

    try
    {
        AESCalculatorClient client;

        client.initialize(*pInitializer);

        const char *Data = "Hi There";
        const uint16_t nDataLen = strlen(Data);
        const BYTE HmacKey[16] = {
            0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b,
        };
        const uint16_t nHmacKeyLen = sizeof(HmacKey);


        const std::vector<BYTE>& ciphertext =
                client.encryptSingleBlock(Data, nDataLen, HmacKey, nHmacKeyLen);
        printf("加密后输出ciphertext: ");
        vector<BYTE>::const_iterator i;
        vector<BYTE>::const_iterator j;
        for (i=ciphertext.begin(); i!=ciphertext.end(); i++)
        {
            printf("%02X:", (BYTE) *i);
        }
        printf("\n");

        const std::vector<BYTE>& plaintext =
                client.decryptSingleBlock(ciphertext.data(), ciphertext.size(), HmacKey, nHmacKeyLen);
        printf("解密后输出plaintext: ");
        for (j=plaintext.begin(); j!=plaintext.end(); j++)
        {
            printf("%c", (BYTE) *j);
        }
        printf("\n");
    }
    catch (std::exception& err)
    {
        fprintf(stderr, "Error: %s\n", err.what());
        PrintHelp();
    }

    pInitializer->disconnect();

    return (0);
}

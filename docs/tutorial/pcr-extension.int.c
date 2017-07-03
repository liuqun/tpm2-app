#include <stdio.h>
#include "log.h"
#include "test.h"
#include "sapi/tpm20.h"
static UINT16 get_digest_size(TPM_ALG_ID hash_alg);
#define PCR_8   8
/**
 * This program contains integration test for SAPI Tss2_Sys_PCR_Read
 * and Tss2_Sys_PCR_Extend. This is an use case scenario on PCR extend.
 * First, we will get the list of PCR avaliable through getcapability
 * SAPI. Then, PCR_Read SAPI is called to list out the PCR value and
 * PCR_Extend SAPI is called next to update the PCR value. Last,
 * PCR_Read SAPI is called again to check the PCR values are changed.
 */
int
test_invoke (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_RC rc;
    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA capability_data;
    TPMS_AUTH_COMMAND session_data;
    TSS2_SYS_CMD_AUTHS sessions_data;
    UINT16 i, digest_size;
    TPML_PCR_SELECTION  pcr_selection;
    UINT32 pcr_update_counter_before_extend;
    UINT32 pcr_update_counter_after_extend;
    UINT8 pcr_before_extend[20];
    UINT8 pcr_after_extend[20];
    TPML_DIGEST pcr_values;
    TPML_DIGEST_VALUES digests;
    TPML_PCR_SELECTION pcr_selection_out;
    TPMS_AUTH_COMMAND *session_data_array[1];

    session_data_array[0] = &session_data;
    sessions_data.cmdAuths = &session_data_array[0];
    session_data.sessionHandle = TPM_RS_PW;
    session_data.nonce.t.size = 0;
    session_data.hmac.t.size = 0;
    *( (UINT8 *)((void *)&session_data.sessionAttributes ) ) = 0;

    print_log("PCR Extension tests started.");
    rc = Tss2_Sys_GetCapability(sapi_context, 0, TPM_CAP_PCR_PROPERTIES, TPM_PT_PCR_COUNT, 1, &more_data, &capability_data, 0);
    if (rc != TSS2_RC_SUCCESS)
        print_fail("GetCapability FAILED! Response Code : 0x%x", rc);

    digests.count = 1;
    digests.digests[0].hashAlg = TPM_ALG_SHA1;
    digest_size = get_digest_size( digests.digests[0].hashAlg );

    for( i = 0; i < digest_size; i++ )
    {
        digests.digests[0].digest.sha1[i] = (UINT8)(i % 256);
    }
    pcr_selection.count = 1;
    pcr_selection.pcrSelections[0].hash = TPM_ALG_SHA1;
    pcr_selection.pcrSelections[0].sizeofSelect = 3;
    pcr_selection.pcrSelections[0].pcrSelect[0] = 0;
    pcr_selection.pcrSelections[0].pcrSelect[1] = 0;
    pcr_selection.pcrSelections[0].pcrSelect[2] = 0;
    pcr_selection.pcrSelections[0].pcrSelect[PCR_8 / 8] = 1 << (PCR_8 % 8);

    rc = Tss2_Sys_PCR_Read(sapi_context, 0, &pcr_selection, &pcr_update_counter_before_extend, &pcr_selection_out, &pcr_values, 0);
    if (rc != TSS2_RC_SUCCESS)
        print_fail("PCR_Read FAILED! Response Code : 0x%x", rc);
    memcpy(&(pcr_before_extend[0]), &(pcr_values.digests[0].t.buffer[0]), pcr_values.digests[0].t.size);

    sessions_data.cmdAuthsCount = 1;
    sessions_data.cmdAuths[0] = &session_data;
    rc = Tss2_Sys_PCR_Extend(sapi_context, PCR_8, &sessions_data, &digests, 0);
    if (rc != TSS2_RC_SUCCESS)
        print_fail("PCR_Extend FAILED! Response Code : 0x%x", rc);

    rc = Tss2_Sys_PCR_Read(sapi_context, 0, &pcr_selection, &pcr_update_counter_after_extend, &pcr_selection_out, &pcr_values, 0);
    if (rc != TSS2_RC_SUCCESS)
        print_fail("PCR_Read FAILED! Response Code : 0x%x", rc);
    memcpy(&(pcr_after_extend[0]), &(pcr_values.digests[0].t.buffer[0]), pcr_values.digests[0].t.size);

    if(pcr_update_counter_before_extend == pcr_update_counter_after_extend)
        print_fail("ERROR!! pcr_update_counter didn't change value\n");

    if(memcmp(&(pcr_before_extend[0]), &(pcr_after_extend[0]), 20) == 0)
        print_fail("ERROR!! PCR didn't change value\n");

    print_log("PCR Extension Test Passed!");
    return 0;
}

typedef struct {
    TPM_ALG_ID hash_alg;
    UINT16 size; // Size of digest
} HASH_SIZE_INFO;
UINT16 get_digest_size (TPM_ALG_ID hash_alg)
{
    const HASH_SIZE_INFO HASH_SIZES[] = {
        {TPM_ALG_SHA1, SHA1_DIGEST_SIZE},
        {TPM_ALG_SHA256, SHA256_DIGEST_SIZE},
        {TPM_ALG_SHA384, SHA384_DIGEST_SIZE},
        {TPM_ALG_SHA512, SHA512_DIGEST_SIZE},
        {TPM_ALG_SM3_256, SM3_256_DIGEST_SIZE},
        {TPM_ALG_NULL, 0},
    };
    const int N = sizeof(HASH_SIZES) / sizeof(HASH_SIZE_INFO);
    UINT16 result;
    int i;

    result = 0;
    for( i = 0; i < N; i++ )
    {
        if(HASH_SIZES[i].hash_alg == hash_alg)
        {
            result = HASH_SIZES[i].size;
            break;
        }
    }
    // If hash_alg was not included from the table, return value will be set to 0
    return(result);
}

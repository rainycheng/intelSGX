#ifndef ENCL1_U_H__
#define ENCL1_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_encl1_sample, (const char* str));

sgx_status_t ecall_encl1_AES_GCM_encrypt(sgx_enclave_id_t eid, const char* p_src, uint32_t src_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

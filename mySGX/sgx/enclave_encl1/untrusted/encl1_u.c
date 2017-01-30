#include "encl1_u.h"
#include <errno.h>

typedef struct ms_ecall_encl1_AES_GCM_decrypt_t {
	char* ms_p_src;
	uint32_t ms_src_len;
	char* ms_p_dec;
	uint32_t* ms_dec_len;
} ms_ecall_encl1_AES_GCM_decrypt_t;

typedef struct ms_ocall_encl1_sample_t {
	char* ms_str;
} ms_ocall_encl1_sample_t;

static sgx_status_t SGX_CDECL encl1_ocall_encl1_sample(void* pms)
{
	ms_ocall_encl1_sample_t* ms = SGX_CAST(ms_ocall_encl1_sample_t*, pms);
	ocall_encl1_sample((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_encl1 = {
	1,
	{
		(void*)encl1_ocall_encl1_sample,
	}
};
sgx_status_t ecall_encl1_AES_GCM_decrypt(sgx_enclave_id_t eid, const char* p_src, uint32_t src_len, char* p_dec, uint32_t* dec_len)
{
	sgx_status_t status;
	ms_ecall_encl1_AES_GCM_decrypt_t ms;
	ms.ms_p_src = (char*)p_src;
	ms.ms_src_len = src_len;
	ms.ms_p_dec = p_dec;
	ms.ms_dec_len = dec_len;
	status = sgx_ecall(eid, 0, &ocall_table_encl1, &ms);
	return status;
}


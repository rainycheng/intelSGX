#include "encl1_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_ecall_encl1_AES_GCM_encrypt_t {
	char* ms_p_src;
	uint32_t ms_src_len;
} ms_ecall_encl1_AES_GCM_encrypt_t;

typedef struct ms_ocall_encl1_sample_t {
	char* ms_str;
} ms_ocall_encl1_sample_t;

static sgx_status_t SGX_CDECL sgx_ecall_encl1_AES_GCM_encrypt(void* pms)
{
	ms_ecall_encl1_AES_GCM_encrypt_t* ms = SGX_CAST(ms_ecall_encl1_AES_GCM_encrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_p_src = ms->ms_p_src;
	size_t _len_p_src = _tmp_p_src ? strlen(_tmp_p_src) + 1 : 0;
	char* _in_p_src = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_ecall_encl1_AES_GCM_encrypt_t));
	CHECK_UNIQUE_POINTER(_tmp_p_src, _len_p_src);

	if (_tmp_p_src != NULL) {
		_in_p_src = (char*)malloc(_len_p_src);
		if (_in_p_src == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy((void*)_in_p_src, _tmp_p_src, _len_p_src);
		_in_p_src[_len_p_src - 1] = '\0';
	}
	ecall_encl1_AES_GCM_encrypt((const char*)_in_p_src, ms->ms_src_len);
err:
	if (_in_p_src) free((void*)_in_p_src);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_ecall_encl1_AES_GCM_encrypt, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][1];
} g_dyn_entry_table = {
	1,
	{
		{0, },
	}
};


sgx_status_t SGX_CDECL ocall_encl1_sample(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_encl1_sample_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_encl1_sample_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_encl1_sample_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_encl1_sample_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(0, ms);


	sgx_ocfree();
	return status;
}


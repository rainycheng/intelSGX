#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "encl1.h"
#include "encl1_t.h"  /* print_string */

#include <sgx_tcrypto.h>
#include <sgx_trts.h>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_encl1_sample(buf);
}



/*
 * if we have a complete line in the buffer, process it.
 */

//static int try_read_command(conn *c) {
//    assert(c != NULL);
//    assert(c->rcurr <= (c->rbuf + c->rsize));
//    assert(c->rbytes > 0);
//
//    if (c->protocol == negotiating_prot || c->transport == udp_transport)  {
//        if ((unsigned char)c->rbuf[0] == (unsigned char)PROTOCOL_BINARY_REQ) {
//            c->protocol = binary_prot;
//        } else {
//            c->protocol = ascii_prot;
//        }
//
//        if (settings.verbose > 1) {
//            fprintf(stderr, "%d: Client using the %s protocol\n", c->sfd,
//                    prot_text(c->protocol));
//        }
//    }
//
//    if (c->protocol == binary_prot) {
//        /* Do we have the complete packet header? */
//        if (c->rbytes < sizeof(c->binary_header)) {
//            /* need more data! */
//            return 0;
//        } else {
//#ifdef NEED_ALIGN
//            if (((long)(c->rcurr)) % 8 != 0) {
//                /* must realign input buffer */
//                memmove(c->rbuf, c->rcurr, c->rbytes);
//                c->rcurr = c->rbuf;
//                if (settings.verbose > 1) {
//                    fprintf(stderr, "%d: Realign input buffer\n", c->sfd);
//                }
//            }
//#endif
//            protocol_binary_request_header* req;
//            req = (protocol_binary_request_header*)c->rcurr;
//
//            if (settings.verbose > 1) {
//                /* Dump the packet before we convert it to host order */
//                int ii;
//                fprintf(stderr, "<%d Read binary protocol data:", c->sfd);
//                for (ii = 0; ii < sizeof(req->bytes); ++ii) {
//                    if (ii % 4 == 0) {
//                        fprintf(stderr, "\n<%d   ", c->sfd);
//                    }
//                    fprintf(stderr, " 0x%02x", req->bytes[ii]);
//                }
//                fprintf(stderr, "\n");
//            }
//
//            c->binary_header = *req;
//            c->binary_header.request.keylen = ntohs(req->request.keylen);
//            c->binary_header.request.bodylen = ntohl(req->request.bodylen);
//            c->binary_header.request.cas = ntohll(req->request.cas);
//
//            if (c->binary_header.request.magic != PROTOCOL_BINARY_REQ) {
//                if (settings.verbose) {
//                    fprintf(stderr, "Invalid magic:  %x\n",
//                            c->binary_header.request.magic);
//                }
//                conn_set_state(c, conn_closing);
//                return -1;
//            }
//
//            c->msgcurr = 0;
//            c->msgused = 0;
//            c->iovused = 0;
//            if (add_msghdr(c) != 0) {
//                out_of_memory(c,
//                        "SERVER_ERROR Out of memory allocating headers");
//                return 0;
//            }
//
//            c->cmd = c->binary_header.request.opcode;
//            c->keylen = c->binary_header.request.keylen;
//            c->opaque = c->binary_header.request.opaque;
//            /* clear the returned cas value */
//            c->cas = 0;
//
//            dispatch_bin_command(c);
//
//            c->rbytes -= sizeof(c->binary_header);
//            c->rcurr += sizeof(c->binary_header);
//        }
//    } else {
//        char *el, *cont;
//
//        if (c->rbytes == 0)
//            return 0;
//
//        el = memchr(c->rcurr, '\n', c->rbytes);
//        if (!el) {
//            if (c->rbytes > 1024) {
//                /*
//                 * We didn't have a '\n' in the first k. This _has_ to be a
//                 * large multiget, if not we should just nuke the connection.
//                 */
//                char *ptr = c->rcurr;
//                while (*ptr == ' ') { /* ignore leading whitespaces */
//                    ++ptr;
//                }
//
//                if (ptr - c->rcurr > 100 ||
//                    (strncmp(ptr, "get ", 4) && strncmp(ptr, "gets ", 5))) {
//
//                    conn_set_state(c, conn_closing);
//                    return 1;
//                }
//            }
//
//            return 0;
//        }
//        cont = el + 1;
//        if ((el - c->rcurr) > 1 && *(el - 1) == '\r') {
//            el--;
//        }
//        *el = '\0';
//
//        assert(cont <= (c->rcurr + c->rbytes));
//
//        c->last_cmd_time = current_time;
//        process_command(c, c->rcurr);
//
//        c->rbytes -= (cont - c->rcurr);
//        c->rcurr = cont;
//
//        assert(c->rcurr <= (c->rbuf + c->rsize));
//    }
//
//    return 1;
//}



void ecall_encl1_AES_GCM_decrypt(const char *p_src, uint32_t src_len, char *p_dec, uint32_t dec_len)
{
	const unsigned char gcm_key[16]= {
	        0xee,0xbc,0x1f,0x57,0x48,0x7f,0x51,0x92,0x1c,0x04,0x65,0x66,
	        0x5f,0x8a,0xe6,0xd1,0x65,0x8b,0xb2,0x6d,0xe6,0xf8,0xa0,0x69,
	        0xa3,0x52,0x02,0x93,0xa5,0x72,0x07,0x8f
	};
	const unsigned char gcm_iv[12] = {
	        0x99,0xaa,0x3e,0x68,0xed,0x81,0x73,0xa0,0xee,0xd0,0x66,0x84
	};

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	sgx_aes_gcm_128bit_key_t *p_key;
	//uint8_t *p_src = "My first encryption test!";
//	uint32_t src_len;
	uint8_t *p_dst;
	uint8_t *p_iv;
	uint32_t iv_len;
	uint8_t *p_aad;
	uint32_t aad_len;
	sgx_aes_gcm_128bit_tag_t *p_out_mac;
    uint8_t *p_decrypt;

    p_key = gcm_key;
//    src_len = strlen(p_src);
    p_dst = (uint8_t *)malloc(sizeof(uint8_t)*1000);
    p_iv = gcm_iv;
    iv_len = 12;
    p_aad = NULL;
    aad_len = 0;
    p_out_mac = (sgx_aes_gcm_128bit_tag_t *)malloc(sizeof(sgx_aes_gcm_128bit_tag_t)*1000);

    ret = sgx_rijndael128GCM_encrypt(p_key, p_src, src_len, p_dst, p_iv, iv_len, p_aad, aad_len, p_out_mac);

    if (ret == SGX_SUCCESS){
       printf("AES GCM encryption success!\n");
       printf("Plain txt: %s\n", p_src);
       printf("Encrypted txt: %s\n", p_dst);
       printf("MAC: %s\n", p_out_mac);
    }

    p_decrypt = (uint8_t *)malloc(sizeof(uint8_t)*1000);
    ret = sgx_rijndael128GCM_decrypt(p_key, p_dst, strlen(p_dst),p_decrypt,p_iv, iv_len, p_aad, aad_len, p_out_mac);

    if (ret == SGX_SUCCESS){
    	printf("AES GCM decryption success!\n");
    	printf("Decrypted txt: %s\n", p_decrypt);
    	printf("MAC: %s\n", p_out_mac);
    }
}


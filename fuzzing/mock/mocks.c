#include "mocks.h"
#include <setjmp.h>
#include "zilliqa.h"
// APPs expect a specific length
cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t *length)
{
    (void) cv;
    *length = (size_t) 32;
    return 0x00000000;
}

static try_context_t *G_exception_context = &fuzz_exit_try_ctx;

try_context_t *try_context_get(void)
{
    return G_exception_context;
}

try_context_t *try_context_set(try_context_t *context)
{
    try_context_t *previous = G_exception_context;
    G_exception_context     = context;
    return previous;
}

void __attribute__((noreturn)) os_sched_exit(bolos_task_status_t exit_code) {
    longjmp(fuzz_exit_try_ctx.jmp_buf, 1);
}

void __attribute__((noreturn)) os_lib_end(void) {
    longjmp(fuzz_exit_try_ctx.jmp_buf, 1);
}


handler_fn_t* lookupHandler(uint8_t ins) {
	switch (ins) {
		case INS_GET_VERSION:    return handleGetVersion;
		case INS_GET_PUBLIC_KEY: return handleGetPublicKey;
		case INS_SIGN_TXN:  return handleSignTxn;
		case INS_SIGN_HASH: return handleSignHash;
		default:                 return NULL;
	}
}

size_t strlcat(char *dst, const char *src, size_t size) {
    size_t dst_len = strnlen(dst, size);
    size_t src_len = strlen(src);

    // No space in buffer to append anything
    if (dst_len == size) {
        return size + src_len;
    }

    size_t space_left = size - dst_len - 1;
    size_t i;

    for (i = 0; i < space_left && src[i]; i++) {
        dst[dst_len + i] = src[i];
    }

    dst[dst_len + i] = '\0';

    return dst_len + src_len;
}

extern uint8_t apdu_size_g;
int os_io_rx_evt(unsigned char *buffer, unsigned short buffer_max_length, 
                    unsigned int  *timeout_ms, bool check_se_event) {
    G_io_apdu_buffer[0] = 0x10; //OS_IO_PACKET_TYPE_RAW_APDU
    memcpy(buffer, G_io_apdu_buffer, buffer_max_length);
    // printf("apdu size = %d!\n", apdu_size_g);
    return apdu_size_g;
}

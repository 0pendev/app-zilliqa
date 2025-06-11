#include "mocks.h"
#include <setjmp.h>

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

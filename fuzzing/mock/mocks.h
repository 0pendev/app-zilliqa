#include "cx_errors.h"
#include "ox_ec.h"
#include "os_task.h"
#include <string.h>
#include "exceptions.h"
#include <stdio.h>
#include <stdint.h>

// to simulate exiting makes a long_jump to fuzzer harness
extern try_context_t fuzz_exit_try_ctx;

try_context_t *try_context_get(void);

try_context_t *try_context_set(try_context_t *context);

void __attribute__((noreturn)) os_sched_exit(bolos_task_status_t exit_code);

void __attribute__((noreturn)) os_lib_end(void);

cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t *length);

void nvm_write(void *dst_adr, void *src_adr, unsigned int src_len);

/*
** Extracted from main.c
*/

// The APDU protocol uses a single-byte instruction code (INS) to specify
// which command should be executed. We'll use this code to dispatch on a
// table of function pointers.
#define INS_GET_VERSION    0x01
#define INS_GET_PUBLIC_KEY 0x02
#define INS_SIGN_TXN  0x04
#define INS_SIGN_HASH 0x08
// This is the function signature for a command handler. 'flags' and 'tx' are
// out-parameters that will control the behavior of the next io_exchange call
// in zil_main. It's common to set *flags |= IO_ASYNC_REPLY, but tx is
// typically unused unless the handler is immediately sending a response APDU.
typedef void handler_fn_t(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx);
handler_fn_t handleGetVersion;
handler_fn_t handleGetPublicKey;
handler_fn_t handleSignTxn;
handler_fn_t handleSignHash;
handler_fn_t* lookupHandler(uint8_t ins);

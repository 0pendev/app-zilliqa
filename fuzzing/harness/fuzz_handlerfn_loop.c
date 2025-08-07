#include "exceptions.h"
#include "zilliqa.h"
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "mock/mocks.h"

try_context_t fuzz_exit_try_ctx = {0};

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#message "Use this macro for code only needed in fuzz targets"
#endif

#define MIN_APDU_SIZE 5
uint8_t apdu_size_g;
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < MIN_APDU_SIZE + 1) {
        // Not enough data for even the header size + 1 byte for length
        return -1;
    }

    if (sigsetjmp(fuzz_exit_try_ctx.jmp_buf, 1) != 0) {
        return 0;
    }

    size_t offset = 0;

    while (offset + 1 < size) {
        uint8_t apdu_size = data[offset];
        apdu_size_g = apdu_size;
        offset++;

        if (apdu_size < MIN_APDU_SIZE) {
            // Too small to be a valid APDU
            break;
        }

        if (offset + apdu_size > size) {
            // Not enough bytes left
            break;
        }

        // Prepare buffer to simulate APDU state
        memset(G_io_apdu_buffer, 0, IO_APDU_BUFFER_SIZE);
        size_t to_copy = apdu_size < IO_APDU_BUFFER_SIZE ? apdu_size : IO_APDU_BUFFER_SIZE;
        memcpy(G_io_apdu_buffer, data + offset, to_copy);

        // Lookup handler and run
        handler_fn_t *handlerFn = lookupHandler(G_io_apdu_buffer[OFFSET_INS]);
        if (!handlerFn) {
            // Skip if unknown INS
            offset += apdu_size;
            continue;
        }

        unsigned int flags = 0;
        unsigned int tx = 0;

        handlerFn(
            G_io_apdu_buffer[OFFSET_P1],
            G_io_apdu_buffer[OFFSET_P2],
            G_io_apdu_buffer + OFFSET_CDATA,
            G_io_apdu_buffer[OFFSET_LC],
            &flags,
            &tx
        );

        offset += apdu_size;
    }

    return 0;
}

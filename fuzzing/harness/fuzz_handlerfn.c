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
uint8_t apdu_size_g;

// Fuzz entry point
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct {
    uint8_t io_apdu_buffer[IO_APDU_BUFFER_SIZE];
    io_seph_app_t io_app;
    unsigned int flags;
    unsigned int tx;
  } fuzz_header;
  handler_fn_t *handlerFn = NULL;

  // Fuzzing requirements
  if (size <= sizeof(fuzz_header)) {
    // Not enough size to mock our program states
    return -1;
  }
  if (sigsetjmp(fuzz_exit_try_ctx.jmp_buf, 1) != 0) {
    // We stumbled upon an Exception. We return -1 because we do not consider
    // it an interesting case here. Instead of returning -1 we could make
    // a null dereference that will notify libfuzzer or return 0 as it might
    // be a new path of search.
    return 0;
  }

  // Randomize global states
  memcpy(&fuzz_header, data, sizeof(fuzz_header));
  memcpy(G_io_apdu_buffer, fuzz_header.io_apdu_buffer, IO_APDU_BUFFER_SIZE);
  memcpy(&G_io_app, &fuzz_header.io_app, sizeof(G_io_app));

  // Emulate APDU handling
  handlerFn = lookupHandler(G_io_apdu_buffer[OFFSET_INS]);
  if (!handlerFn) {
    // Prevents saving corpus that do not contain a valid instruction value
    return -1;
  }
  // Runs the instruction handler
  handlerFn(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2],
            G_io_apdu_buffer + OFFSET_CDATA, G_io_apdu_buffer[OFFSET_LC],
            &fuzz_header.flags, &fuzz_header.tx);

  return 0;
}

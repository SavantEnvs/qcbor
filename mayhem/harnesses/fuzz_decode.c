/*==============================================================================
 mayhem/harnesses/fuzz_decode.c -- raw-traversal libFuzzer harness for QCBOR

 Not an upstream file (QCBOR ships no fuzz harness at all -- there is no
 OSS-Fuzz project to crib from). Feeds attacker bytes straight into
 QCBORDecode_Init() and walks the WHOLE tree with QCBORDecode_GetNext() in a
 loop, exactly the pattern QCBOR's own README recommends as "the fastest way
 to decode, and pulls in the least code" (see example.c's comment above
 DecodeEngineSpiffy()). This exercises the CORE decoder: every major type,
 arbitrary nesting, definite AND indefinite-length arrays/maps/strings, tags,
 floats/half-floats, and big numbers -- all of qcbor_decode.c's parsing logic.

 Does no file I/O and touches no absolute paths (SPEC 6.2 item 13) -- the
 only input is the byte buffer libFuzzer hands in.
 =============================================================================*/
#include <stddef.h>
#include <stdint.h>

#include "qcbor/qcbor_decode.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    QCBORDecodeContext DCtx;
    QCBORItem          Item;
    UsefulBufC         Input;

    Input.ptr = Data;
    Input.len = Size;

    QCBORDecode_Init(&DCtx, Input, QCBOR_DECODE_MODE_NORMAL);

    /* Walk every item in the input, however deeply nested, until the
     * decoder reports an error (including the expected "no more items" at
     * a clean end) or a parse failure on malformed/adversarial CBOR --
     * which is exactly the case this harness exists to find. */
    for (;;) {
        QCBORError uErr = QCBORDecode_GetNext(&DCtx, &Item);
        if (uErr != QCBOR_SUCCESS) {
            break;
        }
    }

    /* Finish releases internal resources and reports unclosed
     * arrays/maps; the return code isn't asserted here (this is the raw
     * traversal fuzz target, not the KAT oracle -- see mayhem/test.sh). */
    (void)QCBORDecode_Finish(&DCtx);

    return 0;
}

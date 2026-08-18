/*==============================================================================
 mayhem/harnesses/fuzz_decode_encode.c -- decode-then-re-encode round-trip
 libFuzzer harness for QCBOR.

 Not an upstream file. Complements fuzz_decode.c (the raw traversal target)
 by additionally driving the ENCODER (qcbor_encode.c) on decoder-derived
 values: every item QCBORDecode_GetNext() returns is fed straight back into
 the matching QCBOREncode_AddXxx()/OpenArray/OpenMap call, using indefinite-
 length containers so no upfront item count is needed. This asserts NOTHING
 about the re-encoded bytes (that would require a canonicalization pass QCBOR
 doesn't do) -- it exists purely to exercise the encoder's container-nesting,
 string, and numeric-value paths on attacker-influenced data, which the pure
 decode target above never touches.

 Container nesting is tracked with a small stack keyed off QCBORItem's
 uNestingLevel (bounded by QCBOR_MAX_ARRAY_NESTING = 15, so 32 is a safe
 margin): whenever the incoming item's nesting level is less than what we
 currently have open in the encoder, that means the decoder just walked out
 of one or more arrays/maps, so we close the matching encoder containers
 first. This is the same nesting-level bookkeeping qcbor_decode.h documents
 for detecting container ends without relying on definite-length counts.

 Does no file I/O; only absolute-free, in-memory buffers (SPEC 6.2 item 13).
 =============================================================================*/
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"

/* QCBOR_MAX_ARRAY_NESTING (qcbor_common.h) is 15; leave real headroom. */
#define MAX_DEPTH 32

/* Scratch output buffer for the re-encode. Sized generously; if an input
 * produces more re-encoded bytes than this, QCBOREncode_Finish() reports
 * QCBOR_ERR_BUFFER_TOO_SMALL, which is ignored -- see file header. */
#define ENCODE_BUF_SIZE (1u << 20)

static void close_top(QCBOREncodeContext *pECtx, char kind)
{
    if (kind == 'A') {
        QCBOREncode_CloseArrayIndefiniteLength(pECtx);
    } else {
        QCBOREncode_CloseMapIndefiniteLength(pECtx);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    static uint8_t EncodeBuf[ENCODE_BUF_SIZE];

    QCBORDecodeContext DCtx;
    QCBOREncodeContext ECtx;
    QCBORItem          Item;
    UsefulBufC         Input;
    UsefulBuf          Storage;
    char               stack[MAX_DEPTH];
    int                depth = 0;

    Input.ptr = Data;
    Input.len = Size;
    QCBORDecode_Init(&DCtx, Input, QCBOR_DECODE_MODE_NORMAL);

    Storage.ptr = EncodeBuf;
    Storage.len = sizeof(EncodeBuf);
    QCBOREncode_Init(&ECtx, Storage);

    for (;;) {
        QCBORError uErr = QCBORDecode_GetNext(&DCtx, &Item);
        if (uErr != QCBOR_SUCCESS) {
            break;
        }

        /* Close encoder containers the decoder has walked back out of. */
        while (depth > 0 && depth > Item.uNestingLevel) {
            close_top(&ECtx, stack[depth - 1]);
            depth--;
        }

        switch (Item.uDataType) {
        case QCBOR_TYPE_INT64:
            QCBOREncode_AddInt64(&ECtx, Item.val.int64);
            break;
        case QCBOR_TYPE_UINT64:
            QCBOREncode_AddUInt64(&ECtx, Item.val.uint64);
            break;
        case QCBOR_TYPE_BYTE_STRING:
            QCBOREncode_AddBytes(&ECtx, Item.val.string);
            break;
        case QCBOR_TYPE_TEXT_STRING:
            QCBOREncode_AddText(&ECtx, Item.val.string);
            break;
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
        case QCBOR_TYPE_DOUBLE:
            QCBOREncode_AddDouble(&ECtx, Item.val.dfnum);
            break;
        case QCBOR_TYPE_FLOAT:
            QCBOREncode_AddFloat(&ECtx, Item.val.fnum);
            break;
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
        case QCBOR_TYPE_TRUE:
            QCBOREncode_AddBool(&ECtx, true);
            break;
        case QCBOR_TYPE_FALSE:
            QCBOREncode_AddBool(&ECtx, false);
            break;
        case QCBOR_TYPE_NULL:
            QCBOREncode_AddNULL(&ECtx);
            break;
        case QCBOR_TYPE_UNDEF:
            QCBOREncode_AddUndef(&ECtx);
            break;
        case QCBOR_TYPE_ARRAY:
            if (depth < MAX_DEPTH) {
                QCBOREncode_OpenArrayIndefiniteLength(&ECtx);
                stack[depth++] = 'A';
            }
            break;
        case QCBOR_TYPE_MAP:
            if (depth < MAX_DEPTH) {
                QCBOREncode_OpenMapIndefiniteLength(&ECtx);
                stack[depth++] = 'M';
            }
            break;
        default:
            /* Bignums, tag-derived types (dates, URIs, ...), and other
             * spiffy-only shapes are exercised by the "spiffy" decode
             * path indirectly through fuzz_decode.c's raw traversal
             * (which still calls QCBORDecode_GetNext() on them); skip
             * re-encoding them here to keep this target's surface simple
             * and crash-attributable to container/scalar round-tripping. */
            break;
        }
    }

    /* Close any containers still open (decode stopped mid-tree on error). */
    while (depth > 0) {
        close_top(&ECtx, stack[depth - 1]);
        depth--;
    }

    UsefulBufC Encoded;
    (void)QCBOREncode_Finish(&ECtx, &Encoded);
    (void)QCBORDecode_Finish(&DCtx);

    return 0;
}

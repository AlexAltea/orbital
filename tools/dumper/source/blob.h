/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 */

#ifndef BLOB_H
#define BLOB_H

#include "ksdk.h"

#define BLOB_TRANSFER_NET 1
#define BLOB_TRANSFER_USB 2

typedef struct blob_t {
    struct blob_t *next;
    uint8_t hash[16];
    uint8_t *data;
    size_t size;
} blob_t;

blob_t* blob_add(blob_t *blob);
void blob_hash(blob_t *blob, const uint8_t *data, size_t size);

void blob_transfer_init();
void blob_transfer_close();
void blob_transfer(blob_t *blob, int mode);
void blob_transfer_all(blob_t *blobs, int mode);

#endif /* BLOB_H */

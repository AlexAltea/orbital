/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 */

#include "blob.h"

#include "ksdk.h"
#include "md5.h"
#include "debug.h"

#define BLOBS_ADDR  IP(192,168,2,1);
#define BLOBS_PORT  9021

int blobs_sockfd;

/* blobs */
blob_t* blob_add(blob_t *blob)
{
    blob_t *next = malloc(sizeof(blob_t));
    memset(next, 0, sizeof(blob_t));
    blob->next = next;
    return next;
}

void blob_hash(blob_t *blob, const uint8_t *data, size_t size)
{
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, size);
    MD5_Final(blob->hash, &ctx);
}

void blob_transfer_init()
{
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = BLOBS_ADDR;
    server.sin_port = sceNetHtons(BLOBS_PORT);

    blobs_sockfd = sceNetSocket("blobs", AF_INET, SOCK_STREAM, 0);
    sceNetConnect(blobs_sockfd, (struct sockaddr *)&server, sizeof(server));
}

void blob_transfer_close()
{
    sceNetSocketClose(blobs_sockfd);
}

static void blob_transfer_via_net(blob_t *blob)
{
    sceNetSend(blobs_sockfd, &blob->size, sizeof(blob->size), 0);
    sceNetSend(blobs_sockfd, &blob->hash[0], sizeof(blob->hash), 0);
    sceNetSend(blobs_sockfd, &blob->data[0], blob->size, 0);
}

static void blob_transfer_via_usb(blob_t *blob)
{
    dprintf("Unimplemented\n");
}

void blob_transfer(blob_t *blob, int mode)
{
    if (!blob) {
        return;
    }
    switch (mode) {
    case BLOB_TRANSFER_NET:
        blob_transfer_via_net(blob);
        break;
    case BLOB_TRANSFER_USB:
        blob_transfer_via_usb(blob);
        break;
    default:
        dprintf("Unimplemented\n");
    }
}

void blob_transfer_all(blob_t *blobs, int mode)
{
    while (blobs) {
        if (blobs->data) {
            blob_transfer(blobs, mode);
        }
        blobs = blobs->next;
    }
}

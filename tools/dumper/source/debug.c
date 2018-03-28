/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 */

#include "debug.h"

/* debugging */
#define DEBUG 1
#define DEBUG_ADDR  IP(192,168,2,1);
#define DEBUG_PORT  9022

#define ku_dprintf(...) do { \
    if (kernel) kdprintf(__VA_ARGS__); else dprintf(__VA_ARGS__); \
} while(0)

int debug_sockfd;
char debug_tmp[512];

void debug_init()
{
    if (!DEBUG) return;

    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_len = sizeof(server);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = DEBUG_ADDR;
    server.sin_port = sceNetHtons(DEBUG_PORT);

    debug_sockfd = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
    sceNetConnect(debug_sockfd, (struct sockaddr *)&server, sizeof(server));
}

void debug_close()
{
    if (!DEBUG) return;
    sceNetSocketClose(debug_sockfd);
}

void _dputs(const char *msg)
{
    sceNetSend(debug_sockfd, msg, strlen(msg), 0);
}

void _kdputs(const char *msg)
{
    uint64_t len = strlen(msg);
    memcpy(debug_tmp, msg, len);
    write_args uap;
    uap.fd = debug_sockfd;
    uap.buf = debug_tmp;
    uap.nbyte = len;
    sys_write(curthread(), &uap);
}

void _hexdump(char *desc, void *addr, int len, int kernel) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    if (desc != NULL)
        ku_dprintf ("%s:\n", desc);

    if (len == 0) {
        ku_dprintf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        ku_dprintf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                ku_dprintf ("  %s\n", buff);
            ku_dprintf ("  %04x ", i);
        }
        ku_dprintf (" %02x", pc[i]);
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0) {
        ku_dprintf ("   ");
        i++;
    }
    ku_dprintf ("  %s\n", buff);
}

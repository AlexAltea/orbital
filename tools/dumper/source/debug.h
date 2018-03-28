/**
 * (c) 2017-2018 Alexandro Sanchez Bach.
 * Released under MIT license. Read LICENSE for more details.
 */

#ifndef DEBUG_H
#define DEBUG_H

#include "ksdk.h"

#define dprintf(format, ...)\
    do {\
        char debug_msg[512];\
        snprintf(debug_msg, 512, format, ##__VA_ARGS__);\
        dputs(debug_msg);\
    } while(0)

#define kdprintf(format, ...)\
    do {\
        char debug_msg[512];\
        snprintf(debug_msg, 512, format, ##__VA_ARGS__);\
        kdputs(debug_msg);\
    } while(0)

#define dputs(msg) \
    _dputs(msg);
#define kdputs(msg) \
    _kdputs(msg);
#define hexdump(desc, addr, len) \
    _hexdump((desc), (addr), (len), 0);
#define khexdump(desc, addr, len) \
    _hexdump((desc), (addr), (len), 1);

extern int debug_sockfd;

void debug_init();
void debug_close();

void _dputs(const char *msg);
void _kdputs(const char *msg);
void _hexdump(char *desc, void *addr, int len, int kernel);

#endif

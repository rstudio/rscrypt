#include <cstring>
#include <vector>
#include <iostream>
#include <iomanip>
#include <stdint.h>

/*
 * Translation Table as described in RFC1113
 */
static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * encodeblock
 *
 * encode 3 8-bit binary bytes as 4 '6-bit' characters
 */
void encodeblock( unsigned char in[3], unsigned char out[4], int len ) {
    out[0] = cb64[ in[0] >> 2 ];
    out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

/*
 * decodeblock
 *
 * decode 4 '6-bit' characters to 3 8-bit bytes
 */
void decodeblock(unsigned char in[4], unsigned char out[3], int len) {
    unsigned char *ch = new unsigned char[len];
    for (int i = 0; i < 4; i++)
        ch[i] = strchr(cb64, in[i]) - cb64;

    out[0] = (ch[0] << 2) + ((ch[1] & 0x30) >> 4);
    out[1] = (len > 2 ? ((ch[1] & 0xf) << 4) + ((ch[2] & 0x3c) >> 2) : 0);
    out[2] = (len > 3 ? ((ch[2] & 0x3) << 6) + ch[3] : 0);
    delete [] ch;
}

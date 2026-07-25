/* ========================================================================== */
/**
 * @file    base64.cpp
 * @brief   Base64 encode/decode class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "base64.h"

static const CHAR8 EncodeTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const CHAR8 EncodeTableSafe[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static const UINT8 DecodeTable[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 00-0f
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 10-1f
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f, // 20-2f('+','/')
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, // 30-3f('0'-'9','=')
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, // 40-4f('A'-'O')
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff, // 50-5f('P'-'Z')
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // 60-6f('a'-'o')
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff  // 70-7f('p'-'z')
};
static const UINT8 DecodeTableSafe[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 00-0f
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 10-1f
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, // 20-2f('-')
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff, // 30-3f('0'-'9','=')
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, // 40-4f('A'-'O')
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0x3f, // 50-5f('P'-'Z','_')
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // 60-6f('a'-'o')
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff  // 70-7f('p'-'z')
};


SIZE_T CBase64::Encode(CHAR8 * out, const UINT8 * in, SIZE_T inlen)
{
    SIZE_T outlen = 0;

    while ( inlen >= 3 )
    {
        UINT32 val = (in[0] << 16) | (in[1] << 8) | in[2];
        out[outlen++] = EncodeTable[(val >> 18) & 0x3f];
        out[outlen++] = EncodeTable[(val >> 12) & 0x3f];
        out[outlen++] = EncodeTable[(val >> 6) & 0x3f];
        out[outlen++] = EncodeTable[val & 0x3f];
        in += 3;
        inlen -= 3;
    }

    if ( inlen >= 2 )
    {
        UINT32 val = (in[0] << 8) | in[1];
        out[outlen++] = EncodeTable[(val >> 10) & 0x3f];
        out[outlen++] = EncodeTable[(val >> 4) & 0x3f];
        out[outlen++] = EncodeTable[(val << 2) & 0x3f];
        out[outlen++] = '=';
    }
    else if ( inlen >= 1 )
    {
        out[outlen++] = EncodeTable[(*in >> 2) & 0x3f];
        out[outlen++] = EncodeTable[(*in << 4) & 0x3f];
        out[outlen++] = '=';
        out[outlen++] = '=';
    }

    return outlen;
}


SIZE_T CBase64::EncodeSafe(CHAR8 * out, const UINT8 * in, SIZE_T inlen)
{
    SIZE_T outlen = 0;

    while ( inlen >= 3 )
    {
        UINT32 val = (in[0] << 16) | (in[1] << 8) | in[2];
        out[outlen++] = EncodeTableSafe[(val >> 18) & 0x3f];
        out[outlen++] = EncodeTableSafe[(val >> 12) & 0x3f];
        out[outlen++] = EncodeTableSafe[(val >> 6) & 0x3f];
        out[outlen++] = EncodeTableSafe[val & 0x3f];
        in += 3;
        inlen -= 3;
    }

    if ( inlen >= 2 )
    {
        UINT32 val = (in[0] << 8) | in[1];
        out[outlen++] = EncodeTableSafe[(val >> 10) & 0x3f];
        out[outlen++] = EncodeTableSafe[(val >> 4) & 0x3f];
        out[outlen++] = EncodeTableSafe[(val << 2) & 0x3f];
        out[outlen++] = '=';
    }
    else if ( inlen >= 1 )
    {
        out[outlen++] = EncodeTableSafe[(*in >> 2) & 0x3f];
        out[outlen++] = EncodeTableSafe[(*in << 4) & 0x3f];
        out[outlen++] = '=';
        out[outlen++] = '=';
    }

    return outlen;
}


SIZE_T CBase64::Decode(UINT8 * out, const CHAR8 * in)
{
    UINT8 buf[4];
    SIZE_T buflen = 0;
    SIZE_T outlen = 0;

    while ( *in != '\0' && *in != '=' )
    {
        UINT8 val = DecodeTable[(UINT8)*in++];
        if ( val != 0xff )
        {
            buf[buflen++] = val;
            if ( buflen >= sizeof(buf) )
            {
                out[outlen++] = (UINT8)((buf[0] << 2) | (buf[1] >> 4));
                out[outlen++] = (UINT8)((buf[1] << 4) | (buf[2] >> 2));
                out[outlen++] = (UINT8)((buf[2] << 6) | buf[3]);
                buflen = 0;
            }
        }
    }

    if ( buflen >= 2 )
    {
        out[outlen++] = (UINT8)((buf[0] << 2) | (buf[1] >> 4));
    }
    if ( buflen >= 3 )
    {
        out[outlen++] = (UINT8)((buf[1] << 4) | (buf[2] >> 2));
    }

    return outlen;
}


SIZE_T CBase64::DecodeSafe(UINT8 * out, const CHAR8 * in)
{
    UINT8 buf[4];
    SIZE_T buflen = 0;
    SIZE_T outlen = 0;

    while ( *in != '\0' && *in != '=' )
    {
        UINT8 val = DecodeTableSafe[(UINT8)*in++];
        if ( val != 0xff )
        {
            buf[buflen++] = val;
            if ( buflen >= sizeof(buf) )
            {
                out[outlen++] = (UINT8)((buf[0] << 2) | (buf[1] >> 4));
                out[outlen++] = (UINT8)((buf[1] << 4) | (buf[2] >> 2));
                out[outlen++] = (UINT8)((buf[2] << 6) | buf[3]);
                buflen = 0;
            }
        }
    }

    if ( buflen >= 2 )
    {
        out[outlen++] = (UINT8)((buf[0] << 2) | (buf[1] >> 4));
    }
    if ( buflen >= 3 )
    {
        out[outlen++] = (UINT8)((buf[1] << 4) | (buf[2] >> 2));
    }

    return outlen;
}


/* ========================================================================== */
/**
 * @file    base64.h
 * @brief   Base64 encode/decode class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_BASE64_H_)
#define _BASE64_H_

#include "BasicDefs.h"

class CBase64
{
public:
    static SIZE_T Encode(CHAR8 * out, const UINT8 * in, SIZE_T inlen);
    static SIZE_T EncodeSafe(CHAR8 * out, const UINT8 * in, SIZE_T inlen);
    static SIZE_T Decode(UINT8 * out, const CHAR8 * in);
    static SIZE_T DecodeSafe(UINT8 * out, const CHAR8 * in);
    static SIZE_T EncodeSize(SIZE_T len) { return ((len + 2) / 3) * 4; }
    static SIZE_T DecodeSize(SIZE_T len) { return ((len + 3) / 4) * 3; }
};

#endif /* #if !defined(_BASE64_H_) */


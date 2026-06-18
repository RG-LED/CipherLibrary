/* ========================================================================== */
/**
 * @file    ascon128.h
 * @brief   Ascon-128 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCON128_H_)
#define _ASCON128_H_

#include "asconaead.h"

class CAscon128 : public CAsconAead
{
public:
    VOID Initialize(const UINT8 key[16], const UINT8 nonce[16], const UINT8 * ad = NULL, SIZE_T adlen = 0);
    VOID Encrypt(UINT8 * out, UINT8 tag[16], const UINT8 * message, SIZE_T msglen);
    BOOL Decrypt(UINT8 * out, const UINT8 * cipher, SIZE_T cphlen, const UINT8 tag[16]);
private:
    VOID Finish(UINT8 tag[16]);
};

#endif // #if !defined(_ASCON128_H_)


/* ========================================================================== */
/**
 * @file    asconaead128.h
 * @brief   Ascon-AEAD128 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCONAEAD128_H_)
#define _ASCONAEAD128_H_

#include "asconlebase.h"

class CAsconAead128 : public CAsconLeBase
{
public:
    VOID Initialize(const UINT8 key[16], const UINT8 nonce[16], const UINT8 * ad = NULL, SIZE_T adlen = 0);
    VOID Encrypt(UINT8 * out, UINT8 tag[16], const UINT8 * message, SIZE_T msglen);
    BOOL Decrypt(UINT8 * out, const UINT8 * cipher, SIZE_T cphlen, const UINT8 tag[16]);
private:
    VOID Finish(UINT8 tag[16]);

    UINT64 m_k0;
    UINT64 m_k1;
};

#endif // #if !defined(_ASCONAEAD128_H_)


/* ========================================================================== */
/**
 * @file    shake256.h
 * @brief   SHAKE256 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_SHAKE256_H_)
#define _SHAKE256_H_

#include "shakebase.h"

class CShake256 : public CShakeBase
{
public:
    CShake256() { m_rate = SHAKE256_RATE; }

    VOID Shake256(UINT8 * out, SIZE_T outlen, const UINT8 * in, SIZE_T inlen)
    {
        Shake(out, outlen, in, inlen);
    }
};

#endif // _SHAKE256_H_


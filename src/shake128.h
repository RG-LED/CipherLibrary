/* ========================================================================== */
/**
 * @file    shake128.h
 * @brief   SHAKE128 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_SHAKE128_H_)
#define _SHAKE128_H_

#include "shakebase.h"

class CShake128 : public CShakeBase
{
public:
    CShake128() { m_rate = SHAKE128_RATE; }

    VOID Shake128(UINT8 * out, SIZE_T outlen, const UINT8 * in, SIZE_T inlen)
    {
        Shake(out, outlen, in, inlen);
    }
};

#endif // _SHAKE128_H_


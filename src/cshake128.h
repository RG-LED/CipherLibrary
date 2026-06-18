/* ========================================================================== */
/**
 * @file    cshake128.h
 * @brief   cSHAKE128 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_CSHAKE128_H_)
#define _CSHAKE128_H_

#include "cshakebase.h"

class CcShake128 : public CcShakeBase
{
public:
    CcShake128() { m_rate = SHAKE128_RATE; }
};

#endif // _CSHAKE128_H_


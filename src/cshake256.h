/* ========================================================================== */
/**
 * @file    cshake256.h
 * @brief   cSHAKE256 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_CSHAKE256_H_)
#define _CSHAKE256_H_

#include "cshakebase.h"

class CcShake256 : public CcShakeBase
{
public:
    CcShake256() { m_rate = SHAKE256_RATE; }
};

#endif // _CSHAKE256_H_


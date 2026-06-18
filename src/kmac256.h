/* ========================================================================== */
/**
 * @file    kmac256.h
 * @brief   KMAC256 MAC class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_KMAC256_H_)
#define _KMAC256_H_

#include "kmacbase.h"

class CKmac256 : public CKmacBase
{
public:
    CKmac256() { m_rate = SHAKE256_RATE; }
};

#endif // _KMAC256_H_


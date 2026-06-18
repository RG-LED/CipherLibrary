/* ========================================================================== */
/**
 * @file    kmac128.h
 * @brief   KMAC128 MAC class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_KMAC128_H_)
#define _KMAC128_H_

#include "kmacbase.h"

class CKmac128 : public CKmacBase
{
public:
    CKmac128() { m_rate = SHAKE128_RATE; }
};

#endif // _KMAC128_H_


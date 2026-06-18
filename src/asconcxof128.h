/* ========================================================================== */
/**
 * @file    asconcxof128.h
 * @brief   Ascon-CXOF128 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCONCXOF128_H_)
#define _ASCONCXOF128_H_

#include "asconxof128.h"

class CAsconCxof128 : public CAsconXof128
{
public:
    VOID Initialize(const UINT8 * custom, SIZE_T csmlen);
};

#endif // #if !defined(_ASCONCXOF128_H_)


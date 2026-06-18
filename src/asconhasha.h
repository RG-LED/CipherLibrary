/* ========================================================================== */
/**
 * @file    asconhasha.h
 * @brief   Ascon-HASHA hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCONHASHA_H_)
#define _ASCONHASHA_H_

#include "asconhashbase.h"

class CAsconHasha : public CAsconHashBase
{
public:
    VOID Initialize();
    VOID Finish(UINT8 hash[32]);
};

#endif // #if !defined(_ASCONHASHA_H_)


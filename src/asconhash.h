/* ========================================================================== */
/**
 * @file    asconhash.h
 * @brief   Ascon-HASH hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCONHASH_H_)
#define _ASCONHASH_H_

#include "asconhashbase.h"

class CAsconHash : public CAsconHashBase
{
public:
    VOID Initialize();
    VOID Finish(UINT8 hash[32]);
};

#endif // #if !defined(_ASCONHASH_H_)


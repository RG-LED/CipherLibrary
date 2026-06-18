/* ========================================================================== */
/**
 * @file    asconxofa.h
 * @brief   Ascon-XOFA hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCONXOFA_H_)
#define _ASCONXOFA_H_

#include "asconhashbase.h"

class CAsconXofa : public CAsconHashBase
{
public:
    VOID Initialize();
    VOID Finish();
    VOID Squeeze(UINT8 * out, SIZE_T len);
};

#endif // #if !defined(_ASCONXOFA_H_)


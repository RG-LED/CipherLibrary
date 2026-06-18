/* ========================================================================== */
/**
 * @file    asconxof.h
 * @brief   Ascon-XOF hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCONXOF_H_)
#define _ASCONXOF_H_

#include "asconhashbase.h"

class CAsconXof : public CAsconHashBase
{
public:
    VOID Initialize();
    VOID Finish();
    VOID Squeeze(UINT8 * out, SIZE_T len);
};

#endif // #if !defined(_ASCONXOF_H_)


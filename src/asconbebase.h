/* ========================================================================== */
/**
 * @file    asconbebase.h
 * @brief   Ascon Big-endian base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCONBEBASE_H_)
#define _ASCONBEBASE_H_

#include "asconbase.h"

class CAsconBeBase : public CAsconBase
{
public:

protected:
    static UINT64 BytesToUint64(const UINT8 * bytes, SIZE_T len = 8);
    static VOID Uint64ToBytes(UINT8 * bytes, UINT64 n, SIZE_T len = 8);
};

#endif // #if !defined(_ASCONBEBASE_H_)


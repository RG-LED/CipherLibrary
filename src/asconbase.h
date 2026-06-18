/* ========================================================================== */
/**
 * @file    asconbase.h
 * @brief   Ascon base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCONBASE_H_)
#define _ASCONBASE_H_

#include "BasicDefs.h"

class CAsconBase
{
public:
    CAsconBase();
    ~CAsconBase();

protected:
    VOID Permutation(INT32 rounds);
    UINT64 BytesToUint64BE(const UINT8 * bytes, SIZE_T len = 8);
    VOID Uint64ToBytesBE(UINT8 * bytes, UINT64 n, SIZE_T len = 8);

    // Ascon state: 64 bits x 5 = 320 bits
    UINT64 m_state[5];
};

#endif // #if !defined(_ASCONBASE_H_)


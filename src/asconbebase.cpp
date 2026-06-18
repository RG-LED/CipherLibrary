/* ========================================================================== */
/**
 * @file    asconbebase.cpp
 * @brief   Ascon Big-endian base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asconbebase.h"


UINT64 CAsconBeBase::BytesToUint64(const UINT8 * bytes, SIZE_T len)
{
    UINT64 n = 0;
    for ( SIZE_T i = 0; i < len; i++ )
    {
        n |= ((UINT64)bytes[i] << (56 - i * 8));
    }
    return n;
}


VOID CAsconBeBase::Uint64ToBytes(UINT8 * bytes, UINT64 n, SIZE_T len)
{
    for ( SIZE_T i = 0; i < len; i++ )
    {
        bytes[i] = (UINT8)(n >> (56 - i * 8));
    }
}


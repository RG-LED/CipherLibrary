/* ========================================================================== */
/**
 * @file    asconlebase.cpp
 * @brief   Ascon Little-endian base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asconlebase.h"


UINT64 CAsconLeBase::BytesToUint64(const UINT8 * bytes, SIZE_T len)
{
    UINT64 n = 0;
    for ( SIZE_T i = 0; i < len; i++ )
    {
        n |= ((UINT64)bytes[i] << (i * 8));
    }
    return n;
}


VOID CAsconLeBase::Uint64ToBytes(UINT8 * bytes, UINT64 n, SIZE_T len)
{
    for ( SIZE_T i = 0; i < len; i++ )
    {
        bytes[i] = (UINT8)(n >> (i * 8));
    }
}


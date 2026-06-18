/* ========================================================================== */
/**
 * @file    secure.cpp
 * @brief   functions for secure coding
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "secure.h"

VOID secure_zero(VOID * p, SIZE_T n)
{
    volatile UINT8 * v = (volatile UINT8 *)p; // not to be omitted by optimization
    while ( n-- > 0 )
    {
        *v++ = 0;
    }
}

BOOL secure_equal(const VOID * p, const VOID * q, SIZE_T n)
{
    const UINT8 * a = (const UINT8 *)p;
    const UINT8 * b = (const UINT8 *)q;
    UINT8 diff = 0;

    while ( n-- > 0 )
    {
        diff |= (*a++) ^ (*b++);
    }
    return (diff == 0) ? TRUE : FALSE;
}


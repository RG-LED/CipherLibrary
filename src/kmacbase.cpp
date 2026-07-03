/* ========================================================================== */
/**
 * @file    kmacbase.cpp
 * @brief   KMAC MAC class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "kmacbase.h"
#include "secure.h"


VOID CKmacBase::Initialize(const UINT8 * key, SIZE_T keylen, const UINT8 * custom, SIZE_T customlen)
{
    CcShakeBase::Initialize((UINT8 *)"KMAC", 4, custom, customlen);

    SIZE_T total;

    total = EncodeInteger(m_rate); // bytes
    total += EncodeString(key, keylen);
    Padding(total);
}


VOID CKmacBase::Finish(UINT8 * out, SIZE_T outlen)
{
    RightEncode(outlen * 8); // bits

    CcShakeBase::Finish(out, outlen);
}


VOID CKmacBase::RightEncode(SIZE_T len)
{
    UINT8 enc[sizeof(len) + 1];
    UINT32 i = sizeof(enc) - 1;

    do
    {
        i--;
        enc[i] = (UINT8)len;
        len >>= 8;
    }
    while ( len > 0 && i > 0 );
    SIZE_T nbytes = sizeof(enc) - i;
    enc[sizeof(enc) - 1] = (UINT8)(nbytes - 1);
    Absorb(enc + i, nbytes);

    secure_zero(enc, sizeof(enc));
}


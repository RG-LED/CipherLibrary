/* ========================================================================== */
/**
 * @file    fep256base.cpp
 * @brief   P256 finit field number base class for ECDSA
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "fep256base.h"
#include "secure.h"


VOID CFeP256Base::Extract2(CFeP256Base & out, const FOLD_BUF2 & buf)
{
    for ( INT32 i = 0; i < BI256_LIMBS; i++ )
    {
        out.m_Limbs[i] = buf[i];
    }
}

VOID CFeP256Base::Add(FOLD_BUF2 & buf, const CFeP256Base & a, const CFeP256Base & b)
{
    CALC_TYPE c = 0;
    for ( INT32 i = 0; i < BI256_LIMBS; i++ )
    {
        c = (CALC_TYPE)a.m_Limbs[i] + (CALC_TYPE)b.m_Limbs[i] + c;
        buf[i] = (BASE_TYPE)c;
        BI256_SHIFT_RIGHT_LIMB(c);
    }
    buf[BI256_LIMBS] = (BASE_TYPE)c;
}

VOID CFeP256Base::Sub(FOLD_BUF2 & buf, const CFeP256Base & a, const CFeP256Base & b)
{
    CALC_TYPE c = 0;
    for ( INT32 i = 0; i < BI256_LIMBS; i++ )
    {
        c = (CALC_TYPE)a.m_Limbs[i] - (CALC_TYPE)b.m_Limbs[i] - c;
        buf[i] = (BASE_TYPE)c;
        BI256_SHIFT_RIGHT_CARRY(c);
    }
    buf[BI256_LIMBS] = (BASE_TYPE)c;
}


VOID CFeP256Base::ConditionalAdd(FOLD_BUF2 & buf, const CFeP256Base & n)
{
    BASE_TYPE mask = MakeMask((INT32)buf[BI256_LIMBS]); // if negative add it
    CALC_TYPE c = 0;
    BASE_TYPE sum;
    for ( INT32 i = 0; i < BI256_LIMBS; i++ )
    {
        c = (CALC_TYPE)buf[i] + n.m_Limbs[i] + c;
        sum = (BASE_TYPE)c;
        BI256_SHIFT_RIGHT_LIMB(c); // carry
        buf[i] = (buf[i] & ~mask) | (sum & mask);
    }
    buf[BI256_LIMBS] = 0; // must be solved
}


VOID CFeP256Base::ConditionalSub(FOLD_BUF2 & buf, const CFeP256Base & n)
{
    // try subtraction
    CALC_TYPE b = 0;
    BASE_TYPE diff[BI256_LIMBS];
    for ( INT32 i = 0; i < BI256_LIMBS; i++ )
    {
        b = (CALC_TYPE)buf[i] - n.m_Limbs[i] - b;
        diff[i] = (BASE_TYPE)b;
        BI256_SHIFT_RIGHT_CARRY(b); // borrow
    }
    b = (CALC_TYPE)buf[BI256_LIMBS] - b;

    // if no borrow use difference, otherwise original
    BASE_TYPE mask = MakeMask((INT32)b);
    for ( INT32 i = 0; i < BI256_LIMBS; i++ )
    {
        buf[i] = (buf[i] & mask) | (diff[i] & ~mask);
    }
    buf[BI256_LIMBS] = 0; // must be solved
    secure_zero(diff, sizeof(diff));
}


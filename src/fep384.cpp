/* ========================================================================== */
/**
 * @file    fep384.cpp
 * @brief   P384 finit field number class for ECDSA
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "fep384.h"
#include "secure.h"


VOID CFeP384Base::Extract2(CFeP384Base & out, const FOLD_BUF2 & buf)
{
    for ( INT32 i = 0; i < BI384_LIMBS; i++ )
    {
        out.m_Limbs[i] = buf[i];
    }
}

VOID CFeP384Base::Add(FOLD_BUF2 & buf, const CFeP384Base & a, const CFeP384Base & b)
{
    CALC_TYPE c = 0;
    for ( INT32 i = 0; i < BI384_LIMBS; i++ )
    {
        c = (CALC_TYPE)a.m_Limbs[i] + (CALC_TYPE)b.m_Limbs[i] + c;
        buf[i] = (BASE_TYPE)c;
        BI384_SHIFT_RIGHT_LIMB(c);
    }
    buf[BI384_LIMBS] = (BASE_TYPE)c;
}

VOID CFeP384Base::Sub(FOLD_BUF2 & buf, const CFeP384Base & a, const CFeP384Base & b)
{
    CALC_TYPE c = 0;
    for ( INT32 i = 0; i < BI384_LIMBS; i++ )
    {
        c = (CALC_TYPE)a.m_Limbs[i] - (CALC_TYPE)b.m_Limbs[i] - c;
        buf[i] = (BASE_TYPE)c;
        BI384_SHIFT_RIGHT_CARRY(c);
    }
    buf[BI384_LIMBS] = (BASE_TYPE)c;
}


VOID CFeP384Base::ConditionalAdd(FOLD_BUF2 & buf, const CFeP384Base & n)
{
    BASE_TYPE mask = MakeMask((INT32)buf[BI384_LIMBS]); // if negative add it
    CALC_TYPE c = 0;
    BASE_TYPE sum;
    for ( INT32 i = 0; i < BI384_LIMBS; i++ )
    {
        c = (CALC_TYPE)buf[i] + n.m_Limbs[i] + c;
        sum = (BASE_TYPE)c;
        BI384_SHIFT_RIGHT_LIMB(c); // carry
        buf[i] = (buf[i] & ~mask) | (sum & mask);
    }
    buf[BI384_LIMBS] = 0; // must be solved
}


VOID CFeP384Base::ConditionalSub(FOLD_BUF2 & buf, const CFeP384Base & n)
{
    // try subtraction
    CALC_TYPE b = 0;
    BASE_TYPE diff[BI384_LIMBS];
    for ( INT32 i = 0; i < BI384_LIMBS; i++ )
    {
        b = (CALC_TYPE)buf[i] - n.m_Limbs[i] - b;
        diff[i] = (BASE_TYPE)b;
        BI384_SHIFT_RIGHT_CARRY(b); // borrow
    }
    b = (CALC_TYPE)buf[BI384_LIMBS] - b;

    // if no borrow use difference, otherwise use original
    BASE_TYPE mask = MakeMask((INT32)b);
    for ( INT32 i = 0; i < BI384_LIMBS; i++ )
    {
        buf[i] = (buf[i] & mask) | (diff[i] & ~mask);
    }
    buf[BI384_LIMBS] = 0; // must be solved
}


const static UINT8 _P[48] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
const static UINT8 _P2[48] = {
    0xfd, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
const static UINT8 _A[48] = {
    0xfc, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
const static UINT8 _B[48] = {
    0xef, 0x2a, 0xec, 0xd3, 0xed, 0xc8, 0x85, 0x2a, 0x9d, 0xd1, 0x2e, 0x8a, 0x8d, 0x39, 0x56, 0xc6,
    0x5a, 0x87, 0x13, 0x50, 0x8f, 0x08, 0x14, 0x03, 0x12, 0x41, 0x81, 0xfe, 0x6e, 0x9c, 0x1d, 0x18,
    0x19, 0x2d, 0xf8, 0xe3, 0x6b, 0x05, 0x8e, 0x98, 0xe4, 0xe7, 0x3e, 0xe2, 0xa7, 0x2f, 0x31, 0xb3
};
const static UINT8 _Gx[48] = {
    0xb7, 0x0a, 0x76, 0x72, 0x38, 0x5e, 0x54, 0x3a, 0x6c, 0x29, 0x55, 0xbf, 0x5d, 0xf2, 0x02, 0x55,
    0x38, 0x2a, 0x54, 0x82, 0xe0, 0x41, 0xf7, 0x59, 0x98, 0x9b, 0xa7, 0x8b, 0x62, 0x3b, 0x1d, 0x6e,
    0x74, 0xad, 0x20, 0xf3, 0x1e, 0xc7, 0xb1, 0x8e, 0x37, 0x05, 0x8b, 0xbe, 0x22, 0xca, 0x87, 0xaa
};
const static UINT8 _Gy[48] = {
    0x5f, 0x0e, 0xea, 0x90, 0x7c, 0x1d, 0x43, 0x7a, 0x9d, 0x81, 0x7e, 0x1d, 0xce, 0xb1, 0x60, 0x0a,
    0xc0, 0xb8, 0xf0, 0xb5, 0x13, 0x31, 0xda, 0xe9, 0x7c, 0x14, 0x9a, 0x28, 0xbd, 0x1d, 0xf4, 0xf8,
    0x29, 0xdc, 0x92, 0x92, 0xbf, 0x98, 0x9e, 0x5d, 0x6f, 0x2c, 0x26, 0x96, 0x4a, 0xde, 0x17, 0x36
};

CFeP384 CFeP384::P(_P);
CFeP384 CFeP384::P2(_P2);
CFeP384 CFeP384::A(_A);
CFeP384 CFeP384::B(_B);
CFeP384 CFeP384::Gx(_Gx);
CFeP384 CFeP384::Gy(_Gy);

VOID CFeP384::Add(CFeP384 & out, const CFeP384 & a, const CFeP384 & b)
{
    FOLD_BUF2 buf;
    CFeP384Base::Add(buf, a, b);
    ConditionalSub(buf, P);
    Extract2(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeP384::Sub(CFeP384 & out, const CFeP384 & a, const CFeP384 & b)
{
    FOLD_BUF2 buf;
    CFeP384Base::Sub(buf, a, b);
    ConditionalAdd(buf, P);
    Extract2(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeP384::Mul(CFeP384 & out, const CFeP384 & n, const CFeP384 & m)
{
    FOLD_BUF buf;
    CFeBigInt384::Mul(buf, n, m);
    ModP(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeP384::Neg(CFeP384 & out, const CFeP384 & n)
{
    CFeP384 t;
    CFeBigInt384::Sub(t, P, n);
    ModP(out, t);
}

VOID CFeP384::Inv(CFeP384 & out, const CFeP384 & n)
{
    Pow(out, n, P2);
}

VOID CFeP384::Pow(CFeP384 & out, const CFeP384 & a, const CFeP384 & b)
{
    CFeP384 base = a;
    CFeP384 mul;

    out = One;
    for ( INT32 i = 0; i < 384; i++ )
    {
        UINT32 mask = -b.GetBit(i);
        mul = One;
        mul.cmux(base, mask);
        Mul(out, out, mul);
        Mul(base, base, base);
    }
#if 0
// lines above perform the same as followings
    CFeP384 e = b;
    while (e.IsPlus())
    {
        if (e.IsOdd())
        {
            out = out * base;
        }
        base = base * base;
        e.ShiftRight();
    }
#endif
}

VOID CFeP384::Mul(FOLD_BUF & out, const FOLD_BUF & a, const CFeP384 & b)
{
    CFeBigInt384::Mul(out, a, b);
    ModP(out);
}

VOID CFeP384::ModP(CFeP384 & out, const CFeP384 & a)
{
    FOLD_BUF buf;

    Expand(buf, a);
    ModP(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeP384::ModP(CFeP384 & out, FOLD_BUF & buf)
{
    ModP(buf);
    Extract(out, buf);
}

VOID CFeP384::ModP(FOLD_BUF & buf)
{
#if 0
CFeBigInt384::Mod(buf, P);
#else
    FoldP(buf);

    UINT32 gemask = - GreaterEqual(buf, P);
    CFeP384 s = Zero;
    s.cmux(P, gemask);
    CFeBigInt384::Sub(buf, s);
#endif
}

VOID CFeP384::FoldP(FOLD_BUF & buf)
{
    BASE_TYPE hi[BI384_FOLD_SIZE - BI384_LIMBS];
    FOLD_BUF acc;
    for ( INT32 n = 0; n < 2; n++ )
    {
        // setup with 2^0
        secure_zero(acc, sizeof(acc));
        for ( INT32 i = 0; i < BI384_FOLD_SIZE - BI384_LIMBS; i++ )
        {
            acc[i] = hi[i] = buf[i + BI384_LIMBS];
            buf[i + BI384_LIMBS] = 0;
        }

        // 2^128
        CALC_TYPE c = 0;
        for ( INT32 i = 0; i < BI384_FOLD_SIZE - BI384_LIMBS; i++ )
        {
            c += (CALC_TYPE)acc[i + 4] + (CALC_TYPE)hi[i];
            acc[i + 4] = (BASE_TYPE)c;
            BI384_SHIFT_RIGHT_LIMB(c);
        }
        for ( INT32 i = BI384_FOLD_SIZE - BI384_LIMBS + 4; i < BI384_FOLD_SIZE; i++ )
        {
            acc[i] += (BASE_TYPE)c;
            BI384_SHIFT_RIGHT_LIMB(c);
        }

        // 2^96
        c = 0;
        for ( INT32 i = 0; i < BI384_FOLD_SIZE - BI384_LIMBS; i++ )
        {
            c += (CALC_TYPE)acc[i + 3] + (CALC_TYPE)hi[i];
            acc[i + 3] = (BASE_TYPE)c;
            BI384_SHIFT_RIGHT_LIMB(c);
        }
        for ( INT32 i = BI384_FOLD_SIZE - BI384_LIMBS + 3; i < BI384_FOLD_SIZE; i++ )
        {
            acc[i] += (BASE_TYPE)c;
            BI384_SHIFT_RIGHT_LIMB(c);
        }

        // 2^32
        c = 0;
        for ( INT32 i = 0; i < BI384_FOLD_SIZE - BI384_LIMBS; i++ )
        {
            c = (CALC_TYPE)acc[i + 1] - (CALC_TYPE)hi[i] - c;
            acc[i + 1] = (BASE_TYPE)c;
            BI384_SHIFT_RIGHT_CARRY(c);
        }
        for ( INT32 i = BI384_FOLD_SIZE - BI384_LIMBS + 1; i < BI384_FOLD_SIZE; i++ )
        {
            c = (CALC_TYPE)acc[i] - c;
            BI384_SHIFT_RIGHT_CARRY(c);
        }

        // sum them
        c = 0;
        for ( INT32 i = 0; i < BI384_FOLD_SIZE; i++ )
        {
            c += (CALC_TYPE)buf[i] + (CALC_TYPE)acc[i];
            buf[i] = (BASE_TYPE)c;
            BI384_SHIFT_RIGHT_LIMB(c);
        }
    }
}

const static UINT8 _N[48] = {
    0x73, 0x29, 0xc5, 0xcc, 0x6a, 0x19, 0xec, 0xec, 0x7a, 0xa7, 0xb0, 0x48, 0xb2, 0x0d, 0x1a, 0x58,
    0xdf, 0x2d, 0x37, 0xf4, 0x81, 0x4d, 0x63, 0xc7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

const static UINT8 _N2[48] = {
    0x71, 0x29, 0xc5, 0xcc, 0x6a, 0x19, 0xec, 0xec, 0x7a, 0xa7, 0xb0, 0x48, 0xb2, 0x0d, 0x1a, 0x58,
    0xdf, 0x2d, 0x37, 0xf4, 0x81, 0x4d, 0x63, 0xc7, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

const static UINT8 _Nhalf[48] = {
    0xb9, 0x94, 0x62, 0x66, 0xb5, 0x0c, 0x76, 0x76, 0xbd, 0x53, 0x58, 0x24, 0xd9, 0x06, 0x0d, 0xac,
    0xef, 0x96, 0x1b, 0xfa, 0xc0, 0xa6, 0xb1, 0xe3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};

CScalarN384 CScalarN384::N(_N);
CScalarN384 CScalarN384::N2(_N2);
CScalarN384 CScalarN384::Nhalf(_Nhalf);

CScalarN384::CScalarN384()
{
}

VOID CScalarN384::Add(CScalarN384 & out, const CScalarN384 & a, const CScalarN384 & b)
{
    FOLD_BUF2 buf;
    CFeP384Base::Add(buf, a, b);
    ConditionalSub(buf, N);
    Extract2(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarN384::Sub(CScalarN384 & out, const CScalarN384 & a, const CScalarN384 & b)
{
    FOLD_BUF2 buf;
    CFeP384Base::Sub(buf, a, b);
    ConditionalAdd(buf, N);
    Extract2(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarN384::Mul(CScalarN384 & out, const CScalarN384 & a, const CScalarN384 & b)
{
    FOLD_BUF buf;
    Mul(buf, a, b);
    ModN(out, buf);
    secure_zero(buf, sizeof(buf));
}


VOID CScalarN384::Mul(FOLD_BUF & out, const CScalarN384 & a, const CScalarN384 & b)
{
    FOLD_BUF buf;
    Expand(buf, a);
    Mul(out, buf, b);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarN384::Mul(FOLD_BUF & out, const FOLD_BUF & a, const CScalarN384 & b)
{
    CFeBigInt384::Mul(out, a, b);
    CFeBigInt384::Mod(out, N);
}

VOID CScalarN384::ModN(CScalarN384 & out, const CScalarN384 & a)
{
    FOLD_BUF buf;
    Expand(buf, a);
    ModN(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarN384::ModN(CScalarN384 & out, FOLD_BUF & buf)
{
    CFeBigInt384::Mod(buf, N);
    Extract(out, buf);
}

VOID CScalarN384::Inv(CScalarN384 & out, const CScalarN384 & n)
{
    Pow(out, n, N2);
}

VOID CScalarN384::Pow(CScalarN384 & out, const CScalarN384 & a, const CScalarN384 & b)
{
    CScalarN384 base = a;
    CScalarN384 mul;

    out = One;
    for ( INT32 i = 0; i < 384; i++ )
    {
        UINT32 mask = -b.GetBit(i);
        mul = One;
        mul.cmux(base, mask);
        Mul(out, out, mul);
        Mul(base, base, base);
    }
#if 0
// lines above performs the same as followings
    CScalarN384 e = b;
    while (e.IsPlus())
    {
        if (e.IsOdd())
        {
            out = out * base;
        }
        base = base * base;
        e.ShiftRight();
    }
#endif
}

VOID CScalarN384::Normalize()
{
    if ( Compare(*this, Nhalf) > 0 )
    {
        Sub(*this, N, *this);
    }
}

#if 0
VOID CScalarN384::ConditionalSubN()
{ // a -= N (branchless)
    CALC_TYPE b = 0;
    BASE_TYPE diff[BI384_LIMBS];
    for ( INT32 i = 0; i < BI384_LIMBS; i++ )
    {
        b = (CALC_TYPE)m_Limbs[i] - N.m_Limbs[i] - b;
        diff[i] = (BASE_TYPE)b;
        BI384_SHIFT_RIGHT_CARRY(b); // borrow
    }
    // if no borrow use difference, otherwise use original
    BASE_TYPE mask = (BASE_TYPE)(b - 1);
    for ( INT32 i = 0; i < BI384_LIMBS; i++ )
    {
        m_Limbs[i] = (m_Limbs[i] & ~mask) | (diff[i] & mask);
    }
}
#endif


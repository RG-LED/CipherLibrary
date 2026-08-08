/* ========================================================================== */
/**
 * @file    fep256.cpp
 * @brief   P256 finit field number class for ECDSA
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "fep256.h"
#include "secure.h"

const static UINT8 _P[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};
const static UINT8 _P2[32] = {
    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};
const static UINT8 _A[32] = {
    0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};
const static UINT8 _B[32] = {
    0x4b, 0x60, 0xd2, 0x27, 0x3e, 0x3c, 0xce, 0x3b, 0xf6, 0xb0, 0x53, 0xcc, 0xb0, 0x06, 0x1d, 0x65,
    0xbc, 0x86, 0x98, 0x76, 0x55, 0xbd, 0xeb, 0xb3, 0xe7, 0x93, 0x3a, 0xaa, 0xd8, 0x35, 0xc6, 0x5a
};
const static UINT8 _Gx[32] = {
    0x96, 0xc2, 0x98, 0xd8, 0x45, 0x39, 0xa1, 0xf4, 0xa0, 0x33, 0xeb, 0x2d, 0x81, 0x7d, 0x03, 0x77,
    0xf2, 0x40, 0xa4, 0x63, 0xe5, 0xe6, 0xbc, 0xf8, 0x47, 0x42, 0x2c, 0xe1, 0xf2, 0xd1, 0x17, 0x6b
};
const static UINT8 _Gy[32] = {
    0xf5, 0x51, 0xbf, 0x37, 0x68, 0x40, 0xb6, 0xcb, 0xce, 0x5e, 0x31, 0x6b, 0x57, 0x33, 0xce, 0x2b,
    0x16, 0x9e, 0x0f, 0x7c, 0x4a, 0xeb, 0xe7, 0x8e, 0x9b, 0x7f, 0x1a, 0xfe, 0xe2, 0x42, 0xe3, 0x4f
};

CFeP256 CFeP256::P(_P);
CFeP256 CFeP256::P2(_P2);
CFeP256 CFeP256::A(_A);
CFeP256 CFeP256::B(_B);
CFeP256 CFeP256::Gx(_Gx);
CFeP256 CFeP256::Gy(_Gy);

VOID CFeP256::Add(CFeP256 & out, const CFeP256 & a, const CFeP256 & b)
{
    FOLD_BUF2 buf;
    CFeP256Base::Add(buf, a, b);
    ConditionalSub(buf, P);
    Extract2(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeP256::Sub(CFeP256 & out, const CFeP256 & a, const CFeP256 & b)
{
    FOLD_BUF2 buf;
    CFeP256Base::Sub(buf, a, b);
    ConditionalAdd(buf, P);
    Extract2(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeP256::Mul(CFeP256 & out, const CFeP256 & n, const CFeP256 & m)
{
    FOLD_BUF buf;
    CFeBigInt256::Mul(buf, n, m);
    ModP(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeP256::Neg(CFeP256 & out, const CFeP256 & n)
{
    CFeP256 t;
    CFeBigInt256::Sub(t, P, n);
    ModP(out, t);
}

VOID CFeP256::Inv(CFeP256 & out, const CFeP256 & n)
{
    Pow(out, n, P2);
}

VOID CFeP256::Pow(CFeP256 & out, const CFeP256 & a, const CFeP256 & b)
{
    CFeP256 base = a;
    CFeP256 mul;

    out = One;
    for ( INT32 i = 0; i < 256; i++ )
    {
        UINT32 mask = -b.GetBit(i);
        mul = One;
        mul.cmux(base, mask);
        Mul(out, out, mul);
        Mul(base, base, base);
    }
#if 0
// lines above perform the same as followings
    CFeP256 e = b;
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

VOID CFeP256::Mul(FOLD_BUF & out, const FOLD_BUF & a, const CFeP256 & b)
{
    CFeBigInt256::Mul(out, a, b);
    ModP(out);
}

VOID CFeP256::ModP(CFeP256 & out, const CFeP256 & a)
{
    FOLD_BUF buf;

    Expand(buf, a);
    ModP(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeP256::ModP(CFeP256 & out, FOLD_BUF & buf)
{
    ModP(buf);
    Extract(out, buf);
}

VOID CFeP256::ModP(FOLD_BUF & buf)
{
#if 0
CFeBigInt256::Mod(buf, P);
#else
    FoldP(buf);

    UINT32 gemask = - GreaterEqual(buf, P);
    CFeP256 s = Zero;
    s.cmux(P, gemask);
    CFeBigInt256::Sub(buf, s);
#endif
}

VOID CFeP256::FoldP(FOLD_BUF & buf)
{
    BASE_TYPE hi[BI256_FOLD_SIZE - BI256_LIMBS];
    FOLD_BUF acc;
    for ( INT32 n = 0; n < 8; n++ )
    {
        // setup with 2^0
        secure_zero(acc, sizeof(acc));
        for ( INT32 i = 0; i < BI256_FOLD_SIZE - BI256_LIMBS; i++ )
        {
            acc[i] = hi[i] = buf[i + BI256_LIMBS];
            buf[i + BI256_LIMBS] = 0;
        }

        // 2^224
        CALC_TYPE c = 0;
        for ( INT32 i = 0; i < BI256_FOLD_SIZE - BI256_LIMBS; i++ )
        {
            c += (CALC_TYPE)acc[i + 7] + (CALC_TYPE)hi[i];
            acc[i + 7] = (BASE_TYPE)c;
            BI256_SHIFT_RIGHT_LIMB(c);
        }
        for ( INT32 i = BI256_FOLD_SIZE - BI256_LIMBS + 7; i < BI256_FOLD_SIZE; i++ )
        {
            c += (CALC_TYPE)acc[i];
            acc[i] = (BASE_TYPE)c;
            BI256_SHIFT_RIGHT_LIMB(c);
        }

        // 2^192
        c = 0;
        for ( INT32 i = 0; i < BI256_FOLD_SIZE - BI256_LIMBS; i++ )
        {
            c = (CALC_TYPE)acc[i + 6] - (CALC_TYPE)hi[i] - c;
            acc[i + 6] = (BASE_TYPE)c;
            BI256_SHIFT_RIGHT_CARRY(c);
        }
        for ( INT32 i = BI256_FOLD_SIZE - BI256_LIMBS + 6; i < BI256_FOLD_SIZE; i++ )
        {
            c = (CALC_TYPE)acc[i] - c;
            acc[i] = (BASE_TYPE)c;
            BI256_SHIFT_RIGHT_CARRY(c);
        }

        // 2^96
        c = 0;
        for ( INT32 i = 0; i < BI256_FOLD_SIZE - BI256_LIMBS; i++ )
        {
            c = (CALC_TYPE)acc[i + 3] - (CALC_TYPE)hi[i] - c;
            acc[i + 3] = (BASE_TYPE)c;
            BI256_SHIFT_RIGHT_CARRY(c);
        }
        for ( INT32 i = BI256_FOLD_SIZE - BI256_LIMBS + 3; i < BI256_FOLD_SIZE; i++ )
        {
            c = (CALC_TYPE)acc[i] - c;
            acc[i] = (BASE_TYPE)c;
            BI256_SHIFT_RIGHT_CARRY(c);
        }

        // sum them
        c = 0;
        for ( INT32 i = 0; i < BI256_FOLD_SIZE; i++ )
        {
            c += (CALC_TYPE)buf[i] + (CALC_TYPE)acc[i];
            buf[i] = (BASE_TYPE)c;
            BI256_SHIFT_RIGHT_LIMB(c);
        }
    }
    secure_zero(hi, sizeof(hi));
    secure_zero(acc, sizeof(acc));
}

const static UINT8 _N[32] = {
    0x51, 0x25, 0x63, 0xfc, 0xc2, 0xca, 0xb9, 0xf3, 0x84, 0x9e, 0x17, 0xa7, 0xad, 0xfa, 0xe6, 0xbc,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

const static UINT8 _N2[32] = {
    0x4f, 0x25, 0x63, 0xfc, 0xc2, 0xca, 0xb9, 0xf3, 0x84, 0x9e, 0x17, 0xa7, 0xad, 0xfa, 0xe6, 0xbc,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

const static UINT8 _Nhalf[32] = {
    0xa8, 0x92, 0x31, 0x7e, 0x61, 0xe5, 0xdc, 0x79, 0x42, 0xcf, 0x8b, 0xd3, 0x56, 0x7d, 0x73, 0xde,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x7f
};

CScalarN256 CScalarN256::N(_N);
CScalarN256 CScalarN256::N2(_N2);
CScalarN256 CScalarN256::Nhalf(_Nhalf);

CScalarN256::CScalarN256()
{
}

VOID CScalarN256::Add(CScalarN256 & out, const CScalarN256 & a, const CScalarN256 & b)
{
    FOLD_BUF2 buf;
    CFeP256Base::Add(buf, a, b);
    ConditionalSub(buf, N);
    Extract2(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarN256::Sub(CScalarN256 & out, const CScalarN256 & a, const CScalarN256 & b)
{
    FOLD_BUF2 buf;
    CFeP256Base::Sub(buf, a, b);
    ConditionalAdd(buf, N);
    Extract2(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarN256::Mul(CScalarN256 & out, const CScalarN256 & a, const CScalarN256 & b)
{
    FOLD_BUF buf;
    Mul(buf, a, b);
    ModN(out, buf);
    secure_zero(buf, sizeof(buf));
}


VOID CScalarN256::Mul(FOLD_BUF & out, const CScalarN256 & a, const CScalarN256 & b)
{
    FOLD_BUF buf;
    Expand(buf, a);
    Mul(out, buf, b);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarN256::Mul(FOLD_BUF & out, const FOLD_BUF & a, const CScalarN256 & b)
{
    CFeBigInt256::Mul(out, a, b);
    CFeBigInt256::Mod(out, N);
}

VOID CScalarN256::ModN(CScalarN256 & out, const CScalarN256 & a)
{
    FOLD_BUF buf;
    Expand(buf, a);
    ModN(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarN256::ModN(CScalarN256 & out, FOLD_BUF & buf)
{
    CFeBigInt256::Mod(buf, N);
    Extract(out, buf);
}

VOID CScalarN256::Inv(CScalarN256 & out, const CScalarN256 & n)
{
    Pow(out, n, N2);
}

VOID CScalarN256::Pow(CScalarN256 & out, const CScalarN256 & a, const CScalarN256 & b)
{
    CScalarN256 base = a;
    CScalarN256 mul;

    out = One;
    for ( INT32 i = 0; i < 256; i++ )
    {
        UINT32 mask = -b.GetBit(i);
        mul = One;
        mul.cmux(base, mask);
        Mul(out, out, mul);
        Mul(base, base, base);
    }
#if 0
// lines above perform the same as followings
    CScalarN256 e = b;
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

VOID CScalarN256::Normalize()
{
    if ( Compare(*this, Nhalf) > 0 )
    {
        Sub(*this, N, *this);
    }
}

#if 0
VOID CScalarN256::ConditionalSubN()
{ // a -= N (branchless)
    CALC_TYPE b = 0;
    BASE_TYPE diff[BI256_LIMBS];
    for ( INT32 i = 0; i < BI256_LIMBS; i++ )
    {
        b = (CALC_TYPE)m_Limbs[i] - N.m_Limbs[i] - b;
        diff[i] = (BASE_TYPE)b;
        BI256_SHIFT_RIGHT_CARRY(b); // borrow
    }
    // if no borrow use difference, otherwise use original
    BASE_TYPE mask = (BASE_TYPE)(b - 1);
    for ( INT32 i = 0; i < BI256_LIMBS; i++ )
    {
        m_Limbs[i] = (m_Limbs[i] & ~mask) | (diff[i] & mask);
    }
}
#endif

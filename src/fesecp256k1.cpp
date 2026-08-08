/* ========================================================================== */
/**
 * @file    fesecp256k1.cpp
 * @brief   SECP256K1 finit field number class for ECDSA
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "fesecp256k1.h"
#include "secure.h"

const static UINT8 _P[32] = {
    0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
const static UINT8 _P2[32] = {
    0x2d, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
const static UINT8 _A[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
const static UINT8 _B[32] = {
    0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
const static UINT8 _Gx[32] = {
    0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59, 0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b, 0x02,
    0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55, 0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66, 0xbe, 0x79
};
const static UINT8 _Gy[32] = {
    0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c, 0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4, 0x17, 0xfd,
    0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d, 0x65, 0xc4, 0xa3, 0x26, 0x77, 0xda, 0x3a, 0x48
};

CFeSecp256k1 CFeSecp256k1::P(_P);
CFeSecp256k1 CFeSecp256k1::P2(_P2);
CFeSecp256k1 CFeSecp256k1::A(_A);
CFeSecp256k1 CFeSecp256k1::B(_B);
CFeSecp256k1 CFeSecp256k1::Gx(_Gx);
CFeSecp256k1 CFeSecp256k1::Gy(_Gy);

VOID CFeSecp256k1::Add(CFeSecp256k1 & out, const CFeSecp256k1 & a, const CFeSecp256k1 & b)
{
    FOLD_BUF2 buf;
    CFeP256Base::Add(buf, a, b);
    ConditionalSub(buf, P);
    Extract2(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeSecp256k1::Sub(CFeSecp256k1 & out, const CFeSecp256k1 & a, const CFeSecp256k1 & b)
{
    FOLD_BUF2 buf;
    CFeP256Base::Sub(buf, a, b);
    ConditionalAdd(buf, P);
    Extract2(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeSecp256k1::Mul(CFeSecp256k1 & out, const CFeSecp256k1 & n, const CFeSecp256k1 & m)
{
    FOLD_BUF buf;
    CFeBigInt256::Mul(buf, n, m);
    ModP(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeSecp256k1::Neg(CFeSecp256k1 & out, const CFeSecp256k1 & n)
{
    CFeSecp256k1 t;
    CFeBigInt256::Sub(t, P, n);
    ModP(out, t);
}

VOID CFeSecp256k1::Inv(CFeSecp256k1 & out, const CFeSecp256k1 & n)
{
    Pow(out, n, P2);
}

VOID CFeSecp256k1::Pow(CFeSecp256k1 & out, const CFeSecp256k1 & a, const CFeSecp256k1 & b)
{
    CFeSecp256k1 base = a;
    CFeSecp256k1 mul;

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
    CFeSecp256k1 e = b;
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

VOID CFeSecp256k1::Mul(FOLD_BUF & out, const FOLD_BUF & a, const CFeSecp256k1 & b)
{
    CFeBigInt256::Mul(out, a, b);
    ModP(out);
}

VOID CFeSecp256k1::ModP(CFeSecp256k1 & out, const CFeSecp256k1 & a)
{
    FOLD_BUF buf;

    Expand(buf, a);
    ModP(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeSecp256k1::ModP(CFeSecp256k1 & out, FOLD_BUF & buf)
{
    ModP(buf);
    Extract(out, buf);
}

VOID CFeSecp256k1::ModP(FOLD_BUF & buf)
{
#if 0
CFeBigInt256::Mod(buf, P);
#else
    FoldP(buf);

    UINT32 gemask = - GreaterEqual(buf, P);
    CFeSecp256k1 s = Zero;
    s.cmux(P, gemask);
    CFeBigInt256::Sub(buf, s);
#endif
}

VOID CFeSecp256k1::FoldP(FOLD_BUF & buf)
{
    BASE_TYPE hi[BI256_FOLD_SIZE - BI256_LIMBS];
    FOLD_BUF acc;
    for ( INT32 n = 0; n < 4; n++ )
    {
        // extract high part starting with 2^32
        secure_zero(hi, sizeof(hi));
        secure_zero(acc, sizeof(acc));
        for ( INT32 i = 0; i < BI256_FOLD_SIZE - BI256_LIMBS; i++ )
        {
            acc[i + 1] = hi[i] = buf[i + BI256_LIMBS];
            buf[i + BI256_LIMBS] = 0;
        }

        // 977
        CALC_TYPE c = 0;
        for ( INT32 i = 0; i < BI256_FOLD_SIZE - BI256_LIMBS; i++ )
        {
            c += (CALC_TYPE)acc[i] + (CALC_TYPE)hi[i] * 977;
            acc[i] = (BASE_TYPE)c;
            BI256_SHIFT_RIGHT_LIMB(c);
        }
        for ( INT32 i = BI256_FOLD_SIZE - BI256_LIMBS; i < BI256_FOLD_SIZE; i++ )
        {
            c += (CALC_TYPE)acc[i];
            acc[i] = (BASE_TYPE)c;
            BI256_SHIFT_RIGHT_LIMB(c);
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
    0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf, 0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

const static UINT8 _N2[32] = {
    0x3f, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf, 0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

const static UINT8 _Nhalf[32] = {
    0xa0, 0x20, 0x1b, 0x68, 0x46, 0x2f, 0xe9, 0xdf, 0x1d, 0x50, 0xa4, 0x57, 0x73, 0x6e, 0x57, 0x5d,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};

CScalarSecp256k1 CScalarSecp256k1::N(_N);
CScalarSecp256k1 CScalarSecp256k1::N2(_N2);
CScalarSecp256k1 CScalarSecp256k1::Nhalf(_Nhalf);

CScalarSecp256k1::CScalarSecp256k1()
{
}

VOID CScalarSecp256k1::Add(CScalarSecp256k1 & out, const CScalarSecp256k1 & a, const CScalarSecp256k1 & b)
{
    FOLD_BUF2 buf;
    CFeP256Base::Add(buf, a, b);
    ConditionalSub(buf, N);
    Extract2(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarSecp256k1::Sub(CScalarSecp256k1 & out, const CScalarSecp256k1 & a, const CScalarSecp256k1 & b)
{
    FOLD_BUF2 buf;
    CFeP256Base::Sub(buf, a, b);
    ConditionalAdd(buf, N);
    Extract2(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarSecp256k1::Mul(CScalarSecp256k1 & out, const CScalarSecp256k1 & a, const CScalarSecp256k1 & b)
{
    FOLD_BUF buf;
    Mul(buf, a, b);
    ModN(out, buf);
    secure_zero(buf, sizeof(buf));
}


VOID CScalarSecp256k1::Mul(FOLD_BUF & out, const CScalarSecp256k1 & a, const CScalarSecp256k1 & b)
{
    FOLD_BUF buf;
    Expand(buf, a);
    Mul(out, buf, b);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarSecp256k1::Mul(FOLD_BUF & out, const FOLD_BUF & a, const CScalarSecp256k1 & b)
{
    CFeBigInt256::Mul(out, a, b);
    CFeBigInt256::Mod(out, N);
}

VOID CScalarSecp256k1::ModN(CScalarSecp256k1 & out, const CScalarSecp256k1 & a)
{
    FOLD_BUF buf;
    Expand(buf, a);
    ModN(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarSecp256k1::ModN(CScalarSecp256k1 & out, FOLD_BUF & buf)
{
    CFeBigInt256::Mod(buf, N);
    Extract(out, buf);
}

VOID CScalarSecp256k1::Inv(CScalarSecp256k1 & out, const CScalarSecp256k1 & n)
{
    Pow(out, n, N2);
}

VOID CScalarSecp256k1::Pow(CScalarSecp256k1 & out, const CScalarSecp256k1 & a, const CScalarSecp256k1 & b)
{
    CScalarSecp256k1 base = a;
    CScalarSecp256k1 mul;

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
    CScalarSecp256k1 e = b;
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

VOID CScalarSecp256k1::Normalize()
{
    if ( Compare(*this, Nhalf) > 0 )
    {
        Sub(*this, N, *this);
    }
}

#if 0
VOID CScalarSecp256k1::ConditionalSubN()
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

/* ========================================================================== */
/**
 * @file    fe25519.cpp
 * @brief   Fe25519 finit field class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "fe25519.h"
#include "secure.h"


const static UINT8 _P[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};
const static UINT8 _P2[32] = {
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};
const static UINT8 _d[32] = {
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52
};
const static UINT8 _d2[32] = {
    0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb, 0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0, 0x00,
    0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19, 0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9, 0x06, 0x24
};
const static UINT8 _SqrtM1[32] = {
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b
};
const static UINT8 _P58[32] = {
    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f
};

CFe25519 CFe25519::P(_P);
CFe25519 CFe25519::P2(_P2);
CFe25519 CFe25519::d(_d);
CFe25519 CFe25519::d2(_d2);
CFe25519 CFe25519::SqrtM1(_SqrtM1);
CFe25519 CFe25519::P58(_P58);

VOID CFe25519::Add(CFe25519 & out, const CFe25519 & n, const CFe25519 & m)
{
    CFe25519 t;
    CFeBigInt256::Add(t, n, m);
    ModP(out, t);
}

VOID CFe25519::Sub(CFe25519 & out, const CFe25519 & n, const CFe25519 & m)
{
    CFe25519 t;
    CFeBigInt256::Add(t, n, P);
    CFeBigInt256::Sub(t, t, m);
    ModP(out, t);
}

VOID CFe25519::Mul(CFe25519 & out, const CFe25519 & n, const CFe25519 & m)
{
    FOLD_BUF buf;
    CFeBigInt256::Mul(buf, n, m);
    ModP(out, buf);
}

VOID CFe25519::Neg(CFe25519 & out, const CFe25519 & n)
{
    CFe25519 t;
    CFeBigInt256::Sub(t, P, n);
    ModP(out, t);
}

VOID CFe25519::Inv(CFe25519 & out, const CFe25519 & n)
{
    Pow(out, n, P2);
}

VOID CFe25519::Pow(CFe25519 & out, const CFe25519 & a, const CFe25519 & b)
{
    CFe25519 base = a;
    CFe25519 mul;

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
// lines above corresponds to the lines below
    CFe25519 e = b;
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

VOID CFe25519::Mul(FOLD_BUF & out, const FOLD_BUF & a, const CFe25519 & b)
{
    CFeBigInt256::Mul(out, a, b);
    ModP(out);
}

VOID CFe25519::ModP(CFe25519 & out, const CFe25519 & a)
{
    FOLD_BUF buf;

    Expand(buf, a);
    ModP(out, buf);
}

VOID CFe25519::ModP(CFe25519 & out, FOLD_BUF & buf)
{
    ModP(buf);
    Extract(out, buf);
}

VOID CFe25519::ModP(FOLD_BUF & buf)
{
#if 0
CFeBigInt256::Mod(buf, P);
return;
#endif
    FoldP(buf);

    UINT32 gemask = - GreaterEqual(buf, P);
    CFe25519 s = Zero;
    s.cmux(P, gemask);
    CFeBigInt256::Sub(buf, s);
}

VOID CFe25519::FoldP(FOLD_BUF & buf)
{
    BASE_TYPE carry = buf[BI256_LIMBS - 1] >> (BI256_BASE_SHIFT - 1);
    for ( INT32 i = BI256_LIMBS; i < BI256_FOLD_SIZE; i++ )
    {
        BASE_TYPE c = buf[i] >> (BI256_BASE_SHIFT - 1);
        buf[i] = (buf[i] << 1) | carry;
        carry = c;
    }

    buf[BI256_LIMBS - 1] &= ((BASE_TYPE)1 << (BI256_BASE_SHIFT - 1)) - 1;
    CALC_TYPE acc = 0;
    for ( INT32 i = 0; i < BI256_LIMBS + 1; i++ )
    {
        acc += (CALC_TYPE)buf[i] + (CALC_TYPE)buf[i + BI256_LIMBS] * 19;
        buf[i + BI256_LIMBS] = 0;
        buf[i] = (BASE_TYPE)acc;
        BI256_SHIFT_RIGHT_LIMB(acc);
    }

    acc = (((CALC_TYPE)buf[BI256_LIMBS - 1] >> (BI256_BASE_SHIFT - 1)) | (CALC_TYPE)(buf[BI256_LIMBS] << 1)) * 19;
    buf[BI256_LIMBS - 1] &= ((BASE_TYPE)1 << (BI256_BASE_SHIFT - 1)) - 1;
    buf[BI256_LIMBS] = 0;
    for ( INT32 i = 0; i < BI256_LIMBS + 1; i++ )
    {
        acc += (CALC_TYPE)buf[i];
        buf[i] = (BASE_TYPE)acc;
        BI256_SHIFT_RIGHT_LIMB(acc);
    }
}

VOID CFe25519::Expand(FOLD_BUF & buf, const CFe25519 & n)
{
    for ( INT32 i = 0; i < BI256_LIMBS; i++ )
    {
        buf[i] = n.m_Limbs[i];
    }
    for ( INT32 i = BI256_LIMBS; i < BI256_FOLD_SIZE; i++ )
    {
        buf[i] = 0;
    }
}

VOID CFe25519::Extract(CFe25519 & out, const FOLD_BUF & buf)
{
    for ( INT32 i = 0; i < BI256_LIMBS; i++ )
    {
        out.m_Limbs[i] = buf[i];
    }
}

const static UINT8 _L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};
const static UINT8 _Llow[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

CScalarL25519 CScalarL25519::L(_L);
CScalarL25519 CScalarL25519::Llow(_Llow);

CScalarL25519::CScalarL25519()
{
}

VOID CScalarL25519::Add(CScalarL25519 & out, const CScalarL25519 & a, const CScalarL25519 & b)
{
    CScalarL25519 t;
    CFeBigInt256::Add(t, a, b);
    ModL(out, t);
    secure_zero(&t, sizeof(t));
}

VOID CScalarL25519::Mul(CScalarL25519 & out, const CScalarL25519 & a, const CScalarL25519 & b)
{
    FOLD_BUF buf;
    Mul(buf, a, b);
    ModL(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarL25519::fromBytesLE64(const UINT8 s[64])
{
    FOLD_BUF buf;
    for ( INT32 i = 0; i < 64 / 4; i++ )
    {
        buf[i] = s[i * 4] | (s[i * 4 + 1] << 8) | (s[i * 4 + 2] << 16) | (s[i * 4 + 3] << 24);
    }
#if BI256_FOLD_SIZE > 64 / 4
    for ( INT32 i = 64 / 4; i < BI256_FOLD_SIZE; i++ )
    {
        buf[i] = 0;
    }
#endif
    ModL(*this, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarL25519::Mul(FOLD_BUF & out, const CScalarL25519 & a, const CScalarL25519 & b)
{
    FOLD_BUF buf;
    Expand(buf, a);
    Mul(out, buf, b);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarL25519::Mul(FOLD_BUF & out, const FOLD_BUF & a, const CScalarL25519 & b)
{
    CFeBigInt256::Mul(out, a, b);
    ModL(out);
}

VOID CScalarL25519::ModL(CScalarL25519 & out, const CScalarL25519 & a)
{
    FOLD_BUF buf;
    Expand(buf, a);
    ModL(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CScalarL25519::ModL(CScalarL25519 & out, FOLD_BUF & buf)
{
    ModL(buf);
    Extract(out, buf);
}

VOID CScalarL25519::ModL(FOLD_BUF & buf)
{
    FoldL(buf);

    UINT32 ge = - GreaterEqual(buf, L);
    CScalarL25519 s = Zero;
    s.cmux(L, ge);
    Sub(buf, s);
    secure_zero(&s, sizeof(s));
}

VOID CScalarL25519::FoldL(FOLD_BUF & buf)
{
    FOLD_BUF sub;

    for ( INT32 k = 0; k < 8; k++ )
    {
        // extract high part (2^253 and higher)
        BASE_TYPE carry = buf[BI256_LIMBS - 1] >> (BI256_BASE_SHIFT - 4);
        for ( INT32 i = 0; i < BI256_FOLD_SIZE - BI256_LIMBS; i++ )
        {
            BASE_TYPE c = buf[i + BI256_LIMBS] >> (BI256_BASE_SHIFT - 4);
            buf[i + BI256_LIMBS] = (BASE_TYPE)((buf[i + BI256_LIMBS] << 4) | carry);
            carry = c;
        }
        SBASE_TYPE sc = carry >> 3;
        sc = (sc | -sc) >> 31; // (sc != 0) ? 0xffffffff : 0

        // calculate high*Llow
        secure_zero(sub, sizeof(sub));
        for ( INT32 i = 0; i < BI256_FOLD_SIZE; i++ )
        {
            CALC_TYPE c = 0;
            CALC_TYPE h = (i + BI256_LIMBS < BI256_FOLD_SIZE) ? buf[i + BI256_LIMBS] : sc;
            for ( INT32 j = 0; j < BI256_FOLD_SIZE; j++ )
            {
                if ( i + j >= BI256_FOLD_SIZE )
                {
                    break;
                }
                CALC_TYPE d = ((j < BI256_LIMBS) ? (CALC_TYPE)Llow.m_Limbs[j] : 0) * h;
                c += sub[i + j] + d;
                sub[i + j] = (BASE_TYPE)c;
                BI256_SHIFT_RIGHT_LIMB(c);
            }
        }

        // clear high part of buf
        buf[BI256_LIMBS - 1] &= ((BASE_TYPE)1 << (BI256_BASE_SHIFT - 4)) - 1;
        for ( INT32 i = BI256_LIMBS; i < BI256_FOLD_SIZE; i++ )
        {
            buf[i] = 0;
        }

        // subtract high*Llow
        SCALC_TYPE c = 0;
        for ( INT32 i = 0; i < BI256_FOLD_SIZE; i++ )
        {
            c += (SCALC_TYPE)buf[i] - (SCALC_TYPE)sub[i];
            buf[i] = (BASE_TYPE)c;
            BI256_SHIFT_RIGHT_LIMB(c);
        }
    }
    secure_zero(sub, sizeof(sub));
}

VOID CScalarL25519::Clamping()
{
#if 1
    Clamping((UINT8 *)m_Limbs);
#else
    m_Limbs[0] &= 0xfffffff8;
    m_Limbs[7] &= 0x7fffffff;
    m_Limbs[7] |= 0x40000000;
#endif
}

VOID CScalarL25519::Clamping(UINT8 s[32])
{
    s[0]  &= 0xf8;
    s[31] &= 0x7f;
    s[31] |= 0x40;
}


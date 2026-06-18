/* ========================================================================== */
/**
 * @file    fe448.cpp
 * @brief   Fe448 finit field class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "fe448.h"
#include "secure.h"

// --- domain parameters (RFC 7748 / 8032) ---
// P = (2^448) - (2^224) - 1; // prime field p
// 726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439
static const UINT8 _P[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
// P2 = P - 2
// 726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365437
static const UINT8 _P2[] = {
    0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
// P14 = (P + 1) / 4
// 181709681073901722637330951972001133588410340171829515070372549795153082041682693171599095924669136482522221115460909340263374504591360
static const UINT8 _P14[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// d = P - 39081; // d = -39081 mod P
// 726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018326358
static const UINT8 _D[] = {
    0x56, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

CFe448 CFe448::P(_P);
CFe448 CFe448::P2(_P2);
CFe448 CFe448::P14(_P14);
CFe448 CFe448::D(_D);

VOID CFe448::ConditionalSubP()
{ // a -= L (branchless)
    CALC_TYPE b = 0;
    BASE_TYPE diff[BI512_LIMBS];
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        b = (CALC_TYPE)m_Limbs[i] - P.m_Limbs[i] - b;
        diff[i] = (BASE_TYPE)b;
        BI512_SHIFT_RIGHT_CARRY(b);
    }
    BASE_TYPE mask = (BASE_TYPE)(b - 1);
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        m_Limbs[i] = (m_Limbs[i] & ~mask) | (diff[i] & mask);
    }
}

VOID CFe448::Add(CFe448 & out, const CFe448 & n, const CFe448 & m)
{
    CFeBigInt512::Add(out, n, m);
    out.ConditionalSubP();
}

VOID CFe448::Sub(CFe448 & out, const CFe448 & n, const CFe448 & m)
{
    CFeBigInt512::Add(out, n, P);
    CFeBigInt512::Sub(out, out, m);
    out.ConditionalSubP();
}

VOID CFe448::Mul(CFe448 & out, const CFe448 & n, const CFe448 & m)
{
    FOLD_BUF buf;
    CFeBigInt512::Mul(buf, n, m);
    ModP(out, buf);
}

VOID CFe448::Neg(CFe448 & out, const CFe448 & n)
{
    CFeBigInt512::Sub(out, P, n);
}

BOOL CFe448::Inv(CFe448 & out, const CFe448 & n)
{
    if ( n.IsZero() )
    {
        out = Zero;
        return FALSE;
    }
    Pow(out, n, P2);
    return TRUE;
}

BOOL CFe448::Sqrt(CFe448 & out, const CFe448 & a)
{
    if ( a.IsZero() )
    {
        out = Zero;
        return TRUE;
    }
    Pow(out, a, CFe448::P14);
    CFe448 t;
    Mul(t, out, out);
    return t == a;
}

#if 0
BOOL CFe448::SqrtRatio(CFe448 &out, const CFe448 &a, const CFe448 &b)
{
    CFe448 inv_b;
    CFe448 x2;

    // inv_b = b^(p-2)
    Inv(inv_b, b);

    // x2 = a/b
    Mul(x2, a, inv_b);

    if ( x2.IsZero() )
    {
        out = Zero;
        return TRUE;
    }

    CFe448 chk;

    Pow(out, x2, P14);                        // x = a^((p+1)/4)
    Mul(chk, out, out);
    Sub(chk, chk, x2);
    if ( !chk.IsZero() )
    {
        out = Zero;
        return FALSE;
    }
    return TRUE;
}
#endif

VOID CFe448::Pow(CFe448 & out, const CFe448 & a, const CFe448 & b)
{
    CFe448 base = a;
    CFe448 mul;

    out = One;
    for ( INT32 i = 0; i < BI512_BYTES * 8; i++ )
    {
        BASE_TYPE mask = -b.GetBit(i);
        mul = One;
        mul.cmux(base, mask);
        Mul(out, out, mul);
        Mul(base, base, base);
    }
}

VOID CFe448::ModP(CFe448 & out, const CFe448 & a)
{
    FOLD_BUF buf;

    Expand(buf, a);
    ModP(out, buf);
}

VOID CFe448::ModP(CFe448 & out, FOLD_BUF & in)
{
#if 0
Mod(buf, P);
Extract(out, in);
#else
    // 1st fold: r = lo + hi + (hi << 224)
    FOLD_BUF buf;
    for ( INT32 i = 0; i < 14; i++ )
    {
        buf[i] = in[i];
    }
    for ( INT32 i = 14; i < BI512_FOLD_SIZE; i++ )
    {
        buf[i] = 0;
    }

    // + hi
    CALC_TYPE c = 0;
    for ( INT32 i = 0; i < BI512_FOLD_SIZE - 14; i++ )
    {
        c = (CALC_TYPE)buf[i] + in[i + 14] + c;
        buf[i] = (BASE_TYPE)c;
        BI512_SHIFT_RIGHT_LIMB(c);
    }
    for ( INT32 i = BI512_FOLD_SIZE - 14; c && i < BI512_FOLD_SIZE; i++ )
    {
        c = (CALC_TYPE)buf[i] + c;
        buf[i] = (BASE_TYPE)c;
        BI512_SHIFT_RIGHT_LIMB(c);
    }

    c = 0;
    for ( INT32 i = 7; i < BI512_FOLD_SIZE - 7; i++ )
    {
        c = (CALC_TYPE)buf[i] + in[i + 7] + c;
        buf[i] = (BASE_TYPE)c;
        BI512_SHIFT_RIGHT_LIMB(c);
    }
    for ( INT32 i = BI512_FOLD_SIZE - 7; c && i < BI512_FOLD_SIZE; i++ )
    {
        c = (CALC_TYPE)buf[i] + c;
        buf[i] = (BASE_TYPE)c;
        BI512_SHIFT_RIGHT_LIMB(c);
    }

    // 2nd fold: take buf[14..20] as hi2 (len=7)
    // r = buf[0..13] + hi2 + (hi2 << 224)
    for ( INT32 i = 0; i < 14; i++ )
    {
        out.m_Limbs[i] = buf[i]; // start from low 14
    }
    for ( INT32 i = 14; i < BI512_LIMBS; i++ )
    {
        out.m_Limbs[i] = 0;
    }

    // + hi2
    c = 0;
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        c = (CALC_TYPE)out.m_Limbs[i] + buf[i + 14] + c;
        out.m_Limbs[i] = (BASE_TYPE)c;
        BI512_SHIFT_RIGHT_LIMB(c);
    }

    // + (hi2 << 224) -> + at offset 7
    c = 0;
    for ( INT32 i = 7; i < BI512_LIMBS; i++ )
    {
        c = (CALC_TYPE)out.m_Limbs[i] + buf[i + 7] + c;
        out.m_Limbs[i] = (BASE_TYPE)c;
        BI512_SHIFT_RIGHT_LIMB(c);
    }

    out.ConditionalSubP();
    out.ConditionalSubP();
#endif
}

///////////////////////////////////////////////////////////////////////////////////////////

// L = (2^446) - 13818066809895115352007386748515426880336692474882178609894547503885; // subgroup order
// 181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779
static const UINT8 _L[] = {
    0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
    0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#if 0
// R2 = 2^(64*14) mod N
// 147668628621171957057112387621969195182055809201420682994801573049888069728093190823333659396398114406917008656190971581810051687095136
static const UINT8 _R2[] = {
    0x60, 0x9B, 0x9B, 0x04, 0x57, 0x92, 0x53, 0xE3, 0xD9, 0x95, 0xB1, 0xC1, 0x4B, 0x2C, 0xF3, 0x7A,
    0x59, 0x18, 0xEA, 0x88, 0x23, 0xDE, 0x66, 0x0D, 0x38, 0xD8, 0xE4, 0x5E, 0x72, 0xCF, 0x17, 0xAE,
    0x44, 0x7C, 0xC4, 0xA3, 0x4B, 0xC1, 0x9C, 0x1A, 0xAF, 0x70, 0xD0, 0xE4, 0xB7, 0xBC, 0x52, 0x20,
    0x29, 0xB7, 0x23, 0xF8, 0x39, 0xA9, 0x02, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// B16m = (2^16)*R2
// 3622323305813145118836624391802828064118981912135513829512196260858429440
static const UINT8 _B16m[] = {
    0x00, 0x00, 0x34, 0xEC, 0x9E, 0x52, 0xB5, 0xF5, 0x1C, 0x72, 0xAB, 0xC2, 0xE9, 0xC8, 0x35, 0xF6,
    0x4C, 0x7A, 0xBF, 0x25, 0xA7, 0x44, 0xD9, 0x92, 0xC4, 0xEE, 0x58, 0x70, 0xD7, 0x0C, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// B32m = (2^32)*R2
// 237392580169770278508077016141190140010101598593713034330911294151618031779840
static const UINT8 _B32m[] = {
    0x00, 0x00, 0x00, 0x00, 0x34, 0xEC, 0x9E, 0x52, 0xB5, 0xF5, 0x1C, 0x72, 0xAB, 0xC2, 0xE9, 0xC8,
    0x35, 0xF6, 0x4C, 0x7A, 0xBF, 0x25, 0xA7, 0x44, 0xD9, 0x92, 0xC4, 0xEE, 0x58, 0x70, 0xD7, 0x0C,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#endif

// mu = floor(b^(2k) / L), b=2^32, k=14
// hex: e0b07b4ad5d673c8ad0aa723d7d833e9fd969c12654b12bb63c15d3308000000...0004
static const UINT8 _MU[] = {
    0xe0, 0xb0, 0x7b, 0x4a, 0xd5, 0xd6, 0x73, 0xc8, 0xad, 0x0a, 0xa7, 0x23, 0xd7, 0xd8, 0x33, 0xe9,
    0xfd, 0x96, 0x9c, 0x12, 0x65, 0x4b, 0x12, 0xbb, 0x63, 0xc1, 0x5d, 0x33, 0x08, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

CScalarL512 CScalarL512::L(_L);
CScalarL512 CScalarL512::MU(_MU);
// CScalarL512 CScalarL512::R2(_R2);
// CScalarL512 CScalarL512::B16m(_B16m);
// CScalarL512 CScalarL512::B32m(_B32m);

// N0 = ED448_N[0] = 0xAB5844F3 (odd)
const CFeBigInt512::BASE_TYPE CScalarL512::Ninv = 0xAE918BC5u;  // -N0^{-1} mod 2^32

#define NLIMBS 14

VOID CScalarL512::ConditionalSubL()
{ // a -= L (branchless)
    CALC_TYPE b = 0;
    BASE_TYPE diff[BI512_LIMBS];
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        b = (CALC_TYPE)m_Limbs[i] - L.m_Limbs[i] - b;
        diff[i] = (BASE_TYPE)b;
        BI512_SHIFT_RIGHT_CARRY(b);
    }

    BASE_TYPE mask = (BASE_TYPE)(b - 1);
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        m_Limbs[i] = (m_Limbs[i] & ~mask) | (diff[i] & mask);
    }
}

// T(2n) -> REDC: out = T * R^{-1} mod N
VOID CScalarL512::ModL(CScalarL512 & out, FOLD_BUF & buf)
{
#if 0
Mod(buf, CScalarL512::L);
Extract(out, buf);
#else
    // 1) q1 = floor(x / b^(k-1)) -> upper part of x
    CScalarL512 q1;
    for ( INT32 i = 0; i < BI512_LIMBS; ++i )
    {
        q1.m_Limbs[i] = buf[i + NLIMBS - 1];
    }

    // 2) q2 = q1 * MU
    FOLD_BUF q2;
    CFeBigInt512::Mul(q2, MU, q1);

    // 3) q3 = floor(q2 / b^(k+1)) -> upper part of q2
    CScalarL512 q3;
    for ( INT32 i = 0; i < BI512_LIMBS; ++i )
    {
        q3.m_Limbs[i] = q2[i + NLIMBS + 1];
    }

    // 4) r1 = x mod b^(k+1) -> lower (k+1) limb
    FOLD_BUF r; // k+1 = 15
    for ( INT32 i = 0; i < BI512_FOLD_SIZE; ++i )
    {
        r[i] = buf[i];
    }

    // 5) r2 = (q3 * L) mod b^(k+1)
    FOLD_BUF q3L;
    CFeBigInt512::Mul(q3L, q3, CScalarL512::L);

    // 6) r = r1 - r2 (mod b^(k+1))
    CALC_TYPE borrow = 0;
    for ( INT32 i = 0; i < BI512_LIMBS; ++i )
    {
        CALC_TYPE t = (CALC_TYPE)r[i] - (CALC_TYPE)q3L[i] - borrow;
        r[i] = (UINT32)t;
        borrow = (t >> (BI512_CALC_SHIFT - 1)) & 1;
    }
    // add b^(k+1) if negative
    if ( borrow )
    {
        CALC_TYPE carry = 1;
        for ( INT32 i = 0; i < BI512_LIMBS; ++i )
        {
            CALC_TYPE t = (CALC_TYPE)r[i] + ((i < BI512_LIMBS) ? L.m_Limbs[i] : 0) + carry;
            r[i] = (BASE_TYPE)t;
            carry = t >> BI512_BASE_SHIFT;
        }
    }

    // 7) copy result into out[0..K-1]
    for ( INT32 i = 0; i < NLIMBS; ++i )
    {
        out.m_Limbs[i] = r[i];
    }
    for ( INT32 i = NLIMBS; i < BI512_LIMBS; ++i )
    {
        out.m_Limbs[i] = 0;
    }

    // 8) normalize r within [0, L) (subtract L once or twice)
    out.ConditionalSubL();
    out.ConditionalSubL();
#endif
}

// z = x * y * R^{-1} mod N
VOID CScalarL512::Mul(CScalarL512 & out, const CScalarL512 & a, const CScalarL512 & b)
{
    FOLD_BUF t;
    CFeBigInt512::Mul(t, a, b);
    ModL(out, t);
}

// ModL: out = a mod N
VOID CScalarL512::ModL(CScalarL512 & out, const CScalarL512 & a)
{
    FOLD_BUF t;
    Expand(t, a);
    ModL(out, t);
}

// x += y (mod N)
VOID CScalarL512::Add(CScalarL512 & out, const CScalarL512 & a, const CScalarL512 & b)
{
    CFeBigInt512::Add(out, a, b);
    out.ConditionalSubL();
}

VOID CScalarL512::Clamping()
{
    m_Limbs[0]  &= 0xfffffffc;
    m_Limbs[13] |= 0x80000000;
    m_Limbs[14]  = 0x00000000;
}

VOID CScalarL512::fromBytesLEClamp(const UINT8 in[114])
{
    fromBytesLE(in, 57);
    Clamping();
}

VOID CScalarL512::fromBytesLE114(const UINT8 in[114])
{
#if 0
FOLD_BUF buf;
foldFromBytesLE(buf, in, 114);
ModL(*this, buf);
#else
    FOLD_BUF x;
    for ( INT32 i = 0; i < 114 / 4; i++ ) /* 114 / 4 = 28.5 */
    {
        x[i] = (BASE_TYPE)(in[4 * i + 0] <<  0) |
               (BASE_TYPE)(in[4 * i + 1] <<  8) |
               (BASE_TYPE)(in[4 * i + 2] << 16) |
               (BASE_TYPE)(in[4 * i + 3] << 24);
    }
    x[28] = (BASE_TYPE)(in[112] << 0) |
            (BASE_TYPE)(in[113] << 8);
    for ( INT32 i = 29; i < BI512_FOLD_SIZE; i++ )
    {
        x[i] = 0;
    }

    secure_zero(m_Limbs, sizeof(m_Limbs));

    INT32 idx = 28;
    while ( idx >= 0 )
    {
        INT32 take = (idx % 13) + 1;

        FOLD_BUF T;

        secure_zero(T, sizeof(T));
        for (INT32 i = 0; i < 14; i++)
        {
            T[take + i] = m_Limbs[i];
        }

        CALC_TYPE c = 0;
        for ( INT32 j = 0; j < take; j++ )
        {
            c = (CALC_TYPE)T[j] + (CALC_TYPE)x[idx - take + 1 + j] + c;
            T[j] = (BASE_TYPE)c;
            BI512_SHIFT_RIGHT_LIMB(c);
        }
        if ( c )
        {
            CALC_TYPE sum = (CALC_TYPE)T[take] + c;
            T[take] = (BASE_TYPE)sum;
            CALC_TYPE carry = sum >> BI512_BASE_SHIFT;
            INT32 pos = take + 1;
            while ( carry && pos < 28 )
            {
                carry = (CALC_TYPE)T[pos] + carry;
                T[pos] = (BASE_TYPE)carry;
                BI512_SHIFT_RIGHT_LIMB(carry);
                pos++;
            }
        }

        ModL(*this, T);
        idx -= take;
    }

    ConditionalSubL();
#endif
}


/* ========================================================================== */
/**
 * @file    RsaBigInt2048.cpp
 * @brief   2048-bit BigInt class for RSA
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "RsaBigInt2048.h"
#include "secure.h"

#define NON_ZERO_MASK(n)    ((UINT32)(((INT32)(n) | -(INT32)(n)) >> 31))

// ---- calculate n0' from inverse (mod 2^32) ----
CRsaBigInt2048::BASE_TYPE CRsaBigInt2048::CalcN0Prime(CRsaBigInt2048::BASE_TYPE n0)
{
    BASE_TYPE x = 1;
    for ( INT32 i = 0; i < 6; i++)
    {
        x = (BASE_TYPE)((CALC_TYPE)x * (2u - (CALC_TYPE)n0 * (CALC_TYPE)x));
    }
    return ~x + 1u;
}

// ---- conditional subtraction (constant-time) ----
VOID CRsaBigInt2048::ConditionalSub(CRsaBigInt2048 & out, const CRsaBigInt2048 & N, BASE_TYPE optmask)
{ // out -= N (branchless)
    CALC_TYPE b = 0;
    BASE_TYPE diff[BI2048_LIMBS];
    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        b = (CALC_TYPE)out.m_Limbs[i] - N.m_Limbs[i] - b;
        diff[i] = (BASE_TYPE)b;
        BI2048_SHIFT_RIGHT_CARRY(b);
    }
    BASE_TYPE mask = (BASE_TYPE)(b - 1) | optmask;
    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        out.m_Limbs[i] = (out.m_Limbs[i] & ~mask) | (diff[i] & mask);
    }
}

// ---- generate R^2 mod N ----
VOID CRsaBigInt2048::CalcR2(CRsaBigInt2048 & R2, const CRsaBigInt2048 & N, INT32 k)
{
    FOLD_BUF buf;
    secure_zero(buf, sizeof(buf));
    buf[k * 2] = 1;  // 2^(32*128) = 2^4096
    CFeBigInt2048::Mod(buf, N);
    Extract(R2, buf);
}

// ---- prepare context ----
BOOL CRsaBigInt2048::PrepareContext(CRsaMontCtx2048 * ctx, const CRsaBigInt2048 & N, INT32 k)
{
    // N must be odd number
    if ( N.GetBit(0) == 0 )
    {
        return FALSE; // even number
    }
    ctx->N = N;
    ctx->n0prime = CalcN0Prime(N.m_Limbs[0]);
    CalcR2(ctx->R2, N, k);
    if ( k == 64 )
    {
        Mul64(ctx->R3, ctx->R2, ctx->R2, ctx);
    }
    else
    {
        Mul32(ctx->R3, ctx->R2, ctx->R2, ctx);
    }
    return TRUE;
}

VOID CRsaBigInt2048::Add(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaBigInt2048 & b, const CRsaBigInt2048 & N)
{
    BASE_TYPE carry;
    CRsaBigInt2048 sub;

    carry = CFeBigInt2048::Add(out, a, b);
    carry |= (CFeBigInt2048::Sub(sub, out, N) == 0);
    out.cmux(sub, NON_ZERO_MASK(carry));
}

VOID CRsaBigInt2048::Sub(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaBigInt2048 & b, const CRsaBigInt2048 & N)
{
    BASE_TYPE carry;
    CRsaBigInt2048 add;
    CRsaBigInt2048 an;
    CRsaBigInt2048 bn;

    carry = CFeBigInt2048::Sub(an, a, N);
    an.cmux(a, NON_ZERO_MASK(carry));
    carry = CFeBigInt2048::Sub(bn, b, N);
    bn.cmux(b, NON_ZERO_MASK(carry));
    carry = CFeBigInt2048::Sub(out, an, bn);
    CFeBigInt2048::Add(add, out, N);
    out.cmux(add, NON_ZERO_MASK(carry));
}

// ---- Montgomery multiplication ----
VOID CRsaBigInt2048::Mul64(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaBigInt2048 & b, const CRsaMontCtx2048 * ctx)
{
    CRsaBigInt2048 ans;

    CALC_TYPE excarry = 0;
    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        // --- t += A * B[i] ---
        CALC_TYPE acc = 0;
        BASE_TYPE bi = b.m_Limbs[i];
        for ( INT32 j = 0; j < BI2048_LIMBS; j++ )
        {
            acc += (CALC_TYPE)ans.m_Limbs[j] + (CALC_TYPE)a.m_Limbs[j] * bi;
            ans.m_Limbs[j] = (BASE_TYPE)acc;
            BI2048_SHIFT_RIGHT_LIMB(acc);
        }
        // t[L] += acc
        CALC_TYPE carry = acc;

        // --- m = (t[0] * n0') mod 2^32 ---
        BASE_TYPE m = (BASE_TYPE)((CALC_TYPE)ans.m_Limbs[0] * (CALC_TYPE)ctx->n0prime); // obtain lower 32 bits

        // --- t += m * N ---
        acc = (CALC_TYPE)ans.m_Limbs[0] + (CALC_TYPE)m * (CALC_TYPE)ctx->N.m_Limbs[0];
        BI2048_SHIFT_RIGHT_LIMB(acc);
        for ( INT32 j = 1; j < BI2048_LIMBS; j++ )
        {
            acc += (CALC_TYPE)ans.m_Limbs[j] + (CALC_TYPE)m * (CALC_TYPE)ctx->N.m_Limbs[j];
            ans.m_Limbs[j - 1] = (BASE_TYPE)acc;
            BI2048_SHIFT_RIGHT_LIMB(acc);
        }
        acc += carry + excarry; // add remaining of previous loop
        ans.m_Limbs[BI2048_LIMBS - 1] = (BASE_TYPE)acc;
        BI2048_SHIFT_RIGHT_LIMB(acc);
        excarry = acc; // store remaining
    }

    ConditionalSub(ans, ctx->N, (BASE_TYPE)NON_ZERO_MASK(excarry));
    ConditionalSub(ans, ctx->N, 0);
    out = ans;
}

// ---- Montgomery multiplication ----
VOID CRsaBigInt2048::Mul32(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaBigInt2048 & b, const CRsaMontCtx2048 * ctx)
{
    CRsaBigInt2048 ans;

    CALC_TYPE excarry = 0;
    for ( INT32 i = 0; i < 32; i++ )
    {
        // --- t += A * B[i] ---
        CALC_TYPE acc = 0;
        BASE_TYPE bi = b.m_Limbs[i];
        for ( INT32 j = 0; j < 32; j++ )
        {
            acc += (CALC_TYPE)ans.m_Limbs[j] + (CALC_TYPE)a.m_Limbs[j] * bi;
            ans.m_Limbs[j] = (BASE_TYPE)acc;
            BI2048_SHIFT_RIGHT_LIMB(acc);
        }
        // t[L] += acc
        CALC_TYPE carry = acc;

        // --- m = (t[0] * n0') mod 2^32 ---
        BASE_TYPE m = (BASE_TYPE)((CALC_TYPE)ans.m_Limbs[0] * (CALC_TYPE)ctx->n0prime); // obtain lower 32 bits

        // --- t += m * N ---
        acc = (CALC_TYPE)ans.m_Limbs[0] + (CALC_TYPE)m * (CALC_TYPE)ctx->N.m_Limbs[0];
        BI2048_SHIFT_RIGHT_LIMB(acc);
        for ( INT32 j = 1; j < 32; j++ )
        {
            acc += (CALC_TYPE)ans.m_Limbs[j] + (CALC_TYPE)m * (CALC_TYPE)ctx->N.m_Limbs[j];
            ans.m_Limbs[j - 1] = (BASE_TYPE)acc;
            BI2048_SHIFT_RIGHT_LIMB(acc);
        }
        acc += carry + excarry; // add remaining of previous loop
        ans.m_Limbs[31] = (BASE_TYPE)acc;
        BI2048_SHIFT_RIGHT_LIMB(acc);
        excarry = acc; // store remaining
    }

    for ( INT32 i = 32; i < BI2048_LIMBS; i++ )
    {
        ans.m_Limbs[i] = 0;
    }

    ConditionalSub(ans, ctx->N, (BASE_TYPE)NON_ZERO_MASK(excarry));

    for ( INT32 i = 32; i < BI2048_LIMBS; i++ )
    {
        ans.m_Limbs[i] = 0;
    }

    ConditionalSub(ans, ctx->N, 0);

    out = ans;
}

// ---- square ----
VOID CRsaBigInt2048::Sqr64(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaMontCtx2048 * ctx)
{
    Mul64(out, a, a, ctx);
}

// ---- square ----
VOID CRsaBigInt2048::Sqr32(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaMontCtx2048 * ctx)
{
    Mul32(out, a, a, ctx);
}

// ---- convert to Montgomery ----
// out = a * R mod N = Mul(a, R^2)
VOID CRsaBigInt2048::ToMont64(const CRsaBigInt2048 & a, const CRsaMontCtx2048 * ctx)
{
    Mul64(*this, a, ctx->R2, ctx);
}

// ---- convert to Montgomery ----
// out = a * R mod N = Mul(a, R^2)
VOID CRsaBigInt2048::ToMont32(const CRsaBigInt2048 & a, const CRsaMontCtx2048 * ctx)
{
    Mul32(*this, a, ctx->R2, ctx);
}

// ---- convert from Montgomery ----
// out = a * 1 mod N = Mul(a, 1)
VOID CRsaBigInt2048::FromMont64(CRsaBigInt2048 & out, const CRsaMontCtx2048 * ctx)
{
    Mul64(out, *this, One, ctx);
}

// ---- convert from Montgomery ----
// out = a * 1 mod N = Mul(a, 1)
VOID CRsaBigInt2048::FromMont32(CRsaBigInt2048 & out, const CRsaMontCtx2048 * ctx)
{
    Mul32(out, *this, One, ctx);
}

VOID CRsaBigInt2048::Reduce2048to1024(const CRsaBigInt2048 & a, const CRsaMontCtx2048 * ctx)
{
    CRsaBigInt2048 upper;
    CRsaBigInt2048 lower;

    for ( INT32 i = 0; i < 32; i++ )
    {
        lower.m_Limbs[i] = a.m_Limbs[i];
        upper.m_Limbs[i] = a.m_Limbs[i + 32];
        lower.m_Limbs[i + 32] = 0;
        upper.m_Limbs[i + 32] = 0;
    }
    Mul32(upper, upper, ctx->R3, ctx);
    Mul32(lower, lower, ctx->R2, ctx);
    Add(*this, upper, lower, ctx->N);
}

BOOL CRsaBigInt2048::Inv(CRsaBigInt2048 & out, const CRsaBigInt2048 & a, const CRsaBigInt2048 & m)
{
    if ( m.IsZero() ) return FALSE;

    CRsaBigInt2048 r0 = m;
    CRsaBigInt2048 r1;
    CFeBigInt2048::Mod(r1, a, m); // r1 = a % m
    if ( r1.IsZero() ) return FALSE;

    // s0 = 0, s1 = 1
    CRsaBigInt2048 s0 = CRsaBigInt2048::Zero;
    CRsaBigInt2048 s1 = CRsaBigInt2048::One;

    // sign flag: TRUE is negative, FALSE is positive
    BOOL s0_neg = FALSE;
    BOOL s1_neg = FALSE;

    while ( !r1.IsZero() )
    {
        CRsaBigInt2048 r2;
        CFeBigInt2048 q = r0.DivModAbs(r1, &r2); // q = r0 / r1, r2 = r0 % r1

        // s2 = s0 - q * s1
        CRsaBigInt2048 qs1;
        CFeBigInt2048::Mul(qs1, q, s1);

        CRsaBigInt2048 s2;
        BOOL s2_neg;

        if ( s0_neg == s1_neg )
        {
            // if same signs, subtract absolute values
            if ( s0 >= qs1 )
            {
                CFeBigInt2048::Sub(s2, s0, qs1);
                s2_neg = s0_neg;
            }
            else
            {
                CFeBigInt2048::Sub(s2, qs1, s0);
                s2_neg = !s0_neg;
            }
        }
        else
        {
            // if different signs, add absolute values
            CFeBigInt2048::Add(s2, s0, qs1);
            s2_neg = s0_neg;
        }

        // update
        r0 = r1;
        r1 = r2;
        s0 = s1;
        s0_neg = s1_neg;
        s1 = s2;
        s1_neg = s2_neg;
    }

    // if gcd(a, m) = r0 is not 1 then no inverse
    if ( r0 != One )
    {
        return FALSE;
    }

    // if negative make it positive
    if ( s0_neg )
    {
        // call Mod in case s0 > m
        CFeBigInt2048::Mod(s0, s0, m);
        if ( !s0.IsZero() )
        {
            CFeBigInt2048::Sub(out, m, s0);
        }
        else
        {
            out = Zero;
        }
    }
    else
    {
        CFeBigInt2048::Mod(out, s0, m);
    }

    return TRUE;
}

#if 0
VOID CRsaBigInt2048::Exp64(CRsaBigInt2048 & out, const CRsaBigInt2048 & base, const CRsaBigInt2048 & exp, const CRsaMontCtx2048 * ctx, INT32 bitlen)
{
    CRsaBigInt2048 A;
    CRsaBigInt2048 X;
    CRsaBigInt2048 tmp;
    X.ToMont64(base, ctx);
    // X = base;
    A.ToMont64(One, ctx); // A=1

    for ( INT32 i = bitlen - 1; i >= 0; --i )
    {
        // A = A^2
        Sqr64(A, A, ctx);
        BASE_TYPE ebit = exp.GetBit(i);
        Mul64(tmp, A, X, ctx);
        BASE_TYPE mask = NON_ZERO_MASK(ebit);
        A.cmux(tmp, mask);
    }
    A.FromMont64(out, ctx);
}
#endif

VOID CRsaBigInt2048::Exp32(CRsaBigInt2048 & out, const CRsaBigInt2048 & base, const CRsaBigInt2048 & exp, const CRsaMontCtx2048 * ctx)
{
    INT32 i = exp.SearchMSB();
    if ( i < 0 )
    {
        out = One;
        return;
    }
    CRsaBigInt2048 table[16];
    CRsaBigInt2048 A;
    // X.ToMont32(base, ctx);
    table[0].ToMont32(One, ctx); // A=1
    table[1] = base;
    for ( INT32 j = 2; j < 16; j++ )
    {
        Mul32(table[j], table[j - 1], base, ctx);
    }

    INT32 index = (exp.m_Limbs[i / 32] >> (i & 0x1c)) & 0x0f;
    A = table[index];

    for ( i -= 4; i >= 0; i -= 4 )
    {
        Sqr32(A, A, ctx);
        Sqr32(A, A, ctx);
        Sqr32(A, A, ctx);
        Sqr32(A, A, ctx);
        index = (exp.m_Limbs[i / 32] >> (i & 0x1c)) & 0x0f;
        Mul32(A, A, table[index], ctx);
    }
    A.FromMont32(out, ctx);
}

// fast version for case e is 32-bit number (e.g. 65537)
VOID CRsaBigInt2048::Exp64_e32(CRsaBigInt2048 & out, const CRsaBigInt2048 & base, BASE_TYPE e, const CRsaMontCtx2048 * ctx)
{
    if ( e == 0 )
    {
        out = One;
        return;
    }

    CRsaBigInt2048 X;
    X.ToMont64(base, ctx);

    INT32 i = 31;
    while ( i >= 0 && ((e >> i) & 1u) == 0 )
    {
        i--;
    }

    CRsaBigInt2048 A = X;

    for ( i--; i >= 0; --i )
    {
        Sqr64(A, A, ctx);
        if ( ((e >> i) & 1u) != 0 )
        {
            Mul64(A, A, X, ctx);
        }
    }
    A.FromMont64(out, ctx);
}

static CHAR8 * ByteToHex(CHAR8 * p, UINT8 b)
{
    static const CHAR8 table[] = "0123456789abcdef";

    *p++ = table[(b >> 4) & 0x0f];
    *p++ = table[b & 0x0f];
    return p;
}

VOID CRsaBigInt2048::ToHexText(CHAR8 * buf) const
{
    const UINT8 * p = (const UINT8 *)m_Limbs;
    BOOL found = FALSE;

    for ( INT32 i = sizeof(m_Limbs) - 1; i >= 0; i-- )
    {
        if ( p[i] != 0 )
        {
            found = TRUE;
        }
        if ( found )
        {
            buf = ByteToHex(buf, p[i]);
        }
    }
    if ( !found )
    {
        *buf++ = '0';
        *buf = '\0';
    }
}


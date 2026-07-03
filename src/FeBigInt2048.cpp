/* ========================================================================== */
/**
 * @file    FeBigInt2048.cpp
 * @brief   2048-bit BigInt class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "FeBigInt2048.h"
#include "secure.h"


CFeBigInt2048 CFeBigInt2048::Zero((UINT32)0);
CFeBigInt2048 CFeBigInt2048::One((UINT32)1);
CFeBigInt2048 CFeBigInt2048::Two((UINT32)2);
CFeBigInt2048 CFeBigInt2048::Three((UINT32)3);

CFeBigInt2048::CFeBigInt2048()
{
    Init();
}

CFeBigInt2048::CFeBigInt2048(UINT32 n)
{
    Init();
    m_Limbs[0] = (BASE_TYPE)n;
}

CFeBigInt2048::CFeBigInt2048(const UINT8 s[BI2048_BYTES])
{
    fromBytesLE(s);
}

CFeBigInt2048::~CFeBigInt2048()
{
    Init();
}

VOID CFeBigInt2048::Init()
{
    secure_zero(m_Limbs, sizeof(m_Limbs));
}

VOID CFeBigInt2048::fromBytesLE(const UINT8 s[], SIZE_T size)
{
    SIZE_T n = (size / 4 < BI2048_LIMBS) ? size / 4 : BI2048_LIMBS;
    SIZE_T i;

    for ( i = 0; i < n; i++ )
    {
        m_Limbs[i] = s[i * 4] | (s[i * 4 + 1] << 8) | (s[i * 4 + 2] << 16) | (s[i * 4 + 3] << 24);
    }
    if ( i < BI2048_LIMBS )
    {
        m_Limbs[i] = 0;
        switch ( size & 3 )
        {
            case 3:
                m_Limbs[i] |= s[i * 4 + 2] << 16;
            case 2:
                m_Limbs[i] |= s[i * 4 + 1] << 8;
            case 1:
                m_Limbs[i] |= s[i * 4];
                break;

            default:
                break;
        }
        for ( i++ ; i < BI2048_LIMBS; i++ )
        {
            m_Limbs[i] = 0;
        }
    }
}

VOID CFeBigInt2048::toBytesLE(UINT8 out[], SIZE_T size) const
{
    SIZE_T n = (size / 4 < BI2048_LIMBS) ? size / 4 : BI2048_LIMBS;
    SIZE_T i;

    for ( i = 0; i < n; i++ )
    {
        out[i * 4]     = (UINT8)m_Limbs[i];
        out[i * 4 + 1] = (UINT8)(m_Limbs[i] >> 8);
        out[i * 4 + 2] = (UINT8)(m_Limbs[i] >> 16);
        out[i * 4 + 3] = (UINT8)(m_Limbs[i] >> 24);
    }
    if ( i < BI2048_LIMBS )
    {
        switch ( size & 3 )
        {
            case 3:
                out[i * 4 + 2] = (UINT8)(m_Limbs[i] >> 16);
            case 2:
                out[i * 4 + 1] = (UINT8)(m_Limbs[i] >> 8);
            case 1:
                out[i * 4] = (UINT8)m_Limbs[i];
                break;
        }
    }
    else
    {
        for ( SIZE_T j = i * 4; j < size; j++ )
        {
            out[j] = 0;
        }
    }
}

VOID CFeBigInt2048::fromBytesBE(const UINT8 s[], SIZE_T size)
{
    INT32 remain = (INT32)size % 4;
    INT32 i;
    INT32 j;

    for ( i = (INT32)size - 4, j = 0; i >= remain && j < BI2048_LIMBS; i -= 4, j++ )
    {
        m_Limbs[j] = s[i + 3] | (s[i + 2] << 8) | (s[i + 1] << 16) | (s[i] << 24);
    }
    if ( j < BI2048_LIMBS )
    {
        m_Limbs[j] = 0;
        switch ( remain )
        {
            case 3:
                m_Limbs[j] |= s[remain - 3] << 16;
            case 2:
                m_Limbs[j] |= s[remain - 2] << 8;
            case 1:
                m_Limbs[j] |= s[remain - 1];
                break;

            default:
                break;
        }
        for ( j++ ; j < BI2048_LIMBS; j++ )
        {
            m_Limbs[j] = 0;
        }
    }
}

VOID CFeBigInt2048::toBytesBE(UINT8 out[], SIZE_T size) const
{
    INT32 remain = (INT32)size % 4;
    INT32 i;
    INT32 j;

    for ( i = (INT32)size - 4, j = 0; i >= remain && j < BI2048_LIMBS; i -= 4, j++ )
    {
        out[i + 3] = (UINT8)(m_Limbs[j]      );
        out[i + 2] = (UINT8)(m_Limbs[j] >>  8);
        out[i + 1] = (UINT8)(m_Limbs[j] >> 16);
        out[i    ] = (UINT8)(m_Limbs[j] >> 24);
    }
    if ( j < BI2048_LIMBS )
    {
        switch ( remain )
        {
            case 3:
                out[remain - 3] = (UINT8)(m_Limbs[i] >> 16);
            case 2:
                out[remain - 2] = (UINT8)(m_Limbs[i] >>  8);
            case 1:
                out[remain - 1] = (UINT8)(m_Limbs[i]      );
                break;
        }
    }
    else
    {
        for ( ; i >= 0; i-- )
        {
            out[i] = 0;
        }
    }
}


CFeBigInt2048::BASE_TYPE CFeBigInt2048::Add(CFeBigInt2048 & out, const CFeBigInt2048 & a, const CFeBigInt2048 & b)
{
    CALC_TYPE c = 0;

    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        c += (CALC_TYPE)a.m_Limbs[i] + (CALC_TYPE)b.m_Limbs[i];
        out.m_Limbs[i] = (BASE_TYPE)c;
        BI2048_SHIFT_RIGHT_LIMB(c);
    }
    return (BASE_TYPE)c;
}

CFeBigInt2048::BASE_TYPE CFeBigInt2048::Sub(CFeBigInt2048 & out, const CFeBigInt2048 & a, const CFeBigInt2048 & b)
{
    CALC_TYPE c = 0;

    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        c = (CALC_TYPE)a.m_Limbs[i] - (CALC_TYPE)b.m_Limbs[i] - c;
        out.m_Limbs[i] = (BASE_TYPE)c;
        BI2048_SHIFT_RIGHT_CARRY(c);
    }
    return (BASE_TYPE)c;
}

#if 0
VOID CFeBigInt2048::Sub(FOLD_BUF & out, const CFeBigInt2048 & a)
{
    CALC_TYPE c = 0;
    for ( INT32 i = 0; i < BI2048_FOLD_SIZE; i++ )
    {
        c = (CALC_TYPE)out[i] - ((i < BI2048_LIMBS) ? (CALC_TYPE)a.m_Limbs[i] : 0) - c;
        out[i] = (BASE_TYPE)c;
        BI2048_SHIFT_RIGHT_CARRY(c);
    }
}
#endif

VOID CFeBigInt2048::Mul(FOLD_BUF & out, const CFeBigInt2048 & a, const CFeBigInt2048 & b)
{
    FOLD_BUF buf;
    Expand(buf, a);
    Mul(out, buf, b);
    secure_zero(buf, sizeof(buf));
}

VOID CFeBigInt2048::Mul(FOLD_BUF & buf, const FOLD_BUF & a, const CFeBigInt2048 & b)
{
    secure_zero(buf, sizeof(FOLD_BUF));
    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        CALC_TYPE c = 0;
        for ( INT32 j = 0; j <= BI2048_LIMBS; j++ )
        {
            if ( i + j >= BI2048_FOLD_SIZE )
            {
                break;
            }
            CALC_TYPE d = (j < BI2048_LIMBS) ? b.m_Limbs[j] : 0;
            c += (CALC_TYPE)buf[i + j] + ((CALC_TYPE)a[i] * d);
            buf[i + j] = (BASE_TYPE)c;
            BI2048_SHIFT_RIGHT_LIMB(c);
        }
    }
}

VOID CFeBigInt2048::Expand(FOLD_BUF & buf, const CFeBigInt2048 & a)
{
    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        buf[i] = a.m_Limbs[i];
    }
    for ( INT32 i = BI2048_LIMBS; i < BI2048_FOLD_SIZE; i++ )
    {
        buf[i] = 0;
    }
}

VOID CFeBigInt2048::Extract(CFeBigInt2048 & out, const FOLD_BUF & buf)
{
    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        out.m_Limbs[i] = buf[i];
    }
}

VOID CFeBigInt2048::cmux(const CFeBigInt2048 &other, BASE_TYPE mask) // constant-time
{
    // this = (mask ? other : this)
    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        m_Limbs[i] ^= mask & (m_Limbs[i] ^ other.m_Limbs[i]);
    }
}

VOID CFeBigInt2048::cswap(CFeBigInt2048 &other, BASE_TYPE mask) // constant-time
{
    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        BASE_TYPE tmp = (m_Limbs[i] ^ other.m_Limbs[i]) & mask;
        m_Limbs[i] ^= tmp;
        other.m_Limbs[i] ^= tmp;
    }
}

VOID CFeBigInt2048::copy(const CFeBigInt2048 & n)
{
    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        m_Limbs[i] = n.m_Limbs[i];
    }
}

INT32 CFeBigInt2048::Compare(const CFeBigInt2048 & a, const CFeBigInt2048 & b)
{
    INT32 ret = 0;

    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        if ( a.m_Limbs[i] > b.m_Limbs[i] )
        {
            ret = 1;
        }
        else if ( a.m_Limbs[i] < b.m_Limbs[i] )
        {
            ret = -1;
        }
    }
    return ret;
}

BOOL CFeBigInt2048::IsZero() const
{
    BASE_TYPE b = 0;
    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        b |= m_Limbs[i];
    }
    return b ? FALSE : TRUE;
}

INT32 CFeBigInt2048::GetBit(INT32 bit) const
{
    INT32 byte = (bit >> 5);
    BASE_TYPE mask = (1u << (bit & 31));
    return (m_Limbs[byte] & mask) != 0 ? 1 : 0;
}

INT32 CFeBigInt2048::GreaterEqual(const FOLD_BUF & a, const CFeBigInt2048 & b)
{
    CALC_TYPE d = 0;

    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        d = (CALC_TYPE)a[i] - (CALC_TYPE)b.m_Limbs[i] - d;
        BI2048_SHIFT_RIGHT_CARRY(d);
    }
    for ( INT32 i = BI2048_LIMBS; i < BI2048_FOLD_SIZE; i++ )
    {
        d = (CALC_TYPE)a[i] - d;
        BI2048_SHIFT_RIGHT_CARRY(d);
    }
    return (INT32)(d ^ 1); /* (d != 0) ? 1 : 0 */
}

VOID CFeBigInt2048::Mod(CFeBigInt2048 & out, const CFeBigInt2048 & a, const CFeBigInt2048 & b)
{
    FOLD_BUF buf;

    Expand(buf, a);
    Mod(buf, b);
    Extract(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeBigInt2048::Mod(FOLD_BUF & buf, const CFeBigInt2048 & a)
{
    INT32 msi_rhs;
    INT32 msi_rest;
    FOLD_BUF buf2;

    for ( msi_rhs = BI2048_LIMBS - 1; msi_rhs >= 0; msi_rhs-- )
    {
        if ( a.m_Limbs[msi_rhs] != 0 )
        {
            break;
        }
    }
    if ( msi_rhs < 0 )
    {
        return;   // div by 0
    }

    for ( msi_rest = BI2048_FOLD_SIZE - 1; msi_rest >= 0; msi_rest-- )
    {
        if ( buf[msi_rest] != 0 )
        {
            break;
        }
    }
    if ( msi_rest < msi_rhs )
    {
        return;
    }

    CALC_TYPE ru = (msi_rhs == 0) ? 0 : 1;

    for ( ; ; )
    {
        while ( msi_rest >= 0 )
        {
            if ( buf[msi_rest] != 0 )
            {
                break;
            }
            msi_rest--;
        }

        if ( msi_rest < msi_rhs )
        {
            break;
        }

        CALC_TYPE d = buf[msi_rest];

        if ( d < (a.m_Limbs[msi_rhs] + ru) )
        {
            if ( msi_rest > msi_rhs )
            {
                d <<= BI2048_BASE_SHIFT;
                msi_rest--;
                d += buf[msi_rest];
            }
            if ( msi_rest <= msi_rhs && d < a.m_Limbs[msi_rhs] )
            {
                break;
            }
        }

        CALC_TYPE e = d / (a.m_Limbs[msi_rhs] + ru);

        if ( e <= 0 )
        {
            if ( msi_rest > msi_rhs )
            {
                continue;
            }
            break;
        }

        INT32 shift = msi_rest - msi_rhs;
        for ( INT32 i = 0; i < BI2048_FOLD_SIZE; i++ )
        {
            INT32 j = i - shift;
            buf2[i] = (j < BI2048_LIMBS && j >= 0) ? a.m_Limbs[j] : 0;
        }
        CALC_TYPE c1 = 0;
        CALC_TYPE c2 = 0;
        for ( INT32 i = 0; i < BI2048_FOLD_SIZE; i++ )
        {
            c1 += (CALC_TYPE)buf2[i] * e;
            buf2[i] = (BASE_TYPE)c1;
            c2 = (CALC_TYPE)buf[i] - (CALC_TYPE)buf2[i] - c2;
            buf[i] = (BASE_TYPE)c2;
            BI2048_SHIFT_RIGHT_LIMB(c1);
            BI2048_SHIFT_RIGHT_CARRY(c2);
        }
        if ( msi_rest < BI2048_FOLD_SIZE - 1 )
        {
            msi_rest++;
        }
    }

    while ( GreaterEqual(buf, a) )
    {
        CALC_TYPE c = 0;
        for ( INT32 i = 0; i < BI2048_FOLD_SIZE; i++ )
        {
            c = (CALC_TYPE)buf[i] - (CALC_TYPE)((i < BI2048_LIMBS) ? a.m_Limbs[i] : 0) - c;
            buf[i] = (BASE_TYPE)c;
            BI2048_SHIFT_RIGHT_CARRY(c);
        }
    }
    secure_zero(buf2, sizeof(buf2));
}

#if 0
VOID CFeBigInt2048::Neg(CFeBigInt2048 & out, const CFeBigInt2048 & a)
{
    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        out.m_Limbs[i] = (BASE_TYPE)~a.m_Limbs[i];
    }

    CALC_TYPE c = 1;

    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        c += out.m_Limbs[i];
        out.m_Limbs[i] = (BASE_TYPE)c;
        BI2048_SHIFT_RIGHT_LIMB(c);
    }
}

VOID CFeBigInt2048::ShiftRight()
{
    CALC_TYPE c;
    CALC_TYPE carry = 0;
    for ( INT32 i = BI2048_LIMBS - 1; i >= 0; i-- )
    {
        c = (CALC_TYPE)(m_Limbs[i] & 1) << (BI2048_BASE_SHIFT - 1);
        m_Limbs[i] = (BASE_TYPE)((m_Limbs[i] >> 1) | carry);
        carry = c;
    }
}

BOOL CFeBigInt2048::IsPlus() const
{
    return !(IsMinus() & IsZero());
}
#endif

CFeBigInt2048 CFeBigInt2048::AddAbs(CALC_TYPE num) const
{
    CFeBigInt2048 a = *this;
    CALC_TYPE d = num;

    for ( INT32 i = 0; d > 0 && i < BI2048_LIMBS; i++ )
    {
        d += (CALC_TYPE)a.m_Limbs[i];
        a.m_Limbs[i] = (BASE_TYPE)d;
        BI2048_SHIFT_RIGHT_LIMB(d);
    }
    return a;
}

CFeBigInt2048 CFeBigInt2048::MulAbs(CALC_TYPE n) const
{
    CFeBigInt2048 a = *this;
    CALC_TYPE acc = 0;

    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        acc += (CALC_TYPE)a.m_Limbs[i] * n;
        a.m_Limbs[i] = (BASE_TYPE)acc;
        BI2048_SHIFT_RIGHT_LIMB(acc);
    }
    return a;
}

CFeBigInt2048 CFeBigInt2048::DivModAbs(const CFeBigInt2048 & rhs, CFeBigInt2048 * remain) const
{
    INT32 msi_rhs;
    INT32 msi_rest;

    for ( msi_rhs = BI2048_LIMBS - 1; msi_rhs >= 0; msi_rhs-- )
    {
        if ( rhs.m_Limbs[msi_rhs] != 0 )
        {
            break;
        }
    }
    if ( msi_rhs < 0 )
    {
        if ( remain != NULL )
        {
            *remain = *this;
        }
        return CFeBigInt2048((UINT32)0);   // div by 0
    }

    for ( msi_rest = BI2048_LIMBS - 1; msi_rest >= 0; msi_rest-- )
    {
        if ( m_Limbs[msi_rest] != 0 )
        {
            break;
        }
    }
    if ( msi_rest < 0 || Compare(*this, rhs) < 0 )
    {
        if ( remain != NULL )
        {
            *remain = *this;
        }
        return CFeBigInt2048((UINT32)0);
    }

    CFeBigInt2048 rest = *this;
    CFeBigInt2048 quot;
    CALC_TYPE ru = (msi_rhs == 0) ? 0 : 1;

    for ( ; ; )
    {
        while ( msi_rest >= 0 )
        {
            if ( rest.m_Limbs[msi_rest] != 0 )
            {
                break;
            }
            msi_rest--;
        }

        if ( msi_rest < msi_rhs )
        {
            break;
        }

        CALC_TYPE d = rest.m_Limbs[msi_rest];

        if ( d < (rhs.m_Limbs[msi_rhs] + ru) )
        {
            if ( msi_rest > msi_rhs )
            {
                d <<= BI2048_BASE_SHIFT;
                msi_rest--;
                d += rest.m_Limbs[msi_rest];
            }
            if ( msi_rest <= msi_rhs && d < rhs.m_Limbs[msi_rhs] )
            {
                break;
            }
        }

        CALC_TYPE e = d / (rhs.m_Limbs[msi_rhs] + ru);

        if ( e <= 0 )
        {
            if ( msi_rest > msi_rhs )
            {
                continue;
            }
            break;
        }

        CFeBigInt2048 b;

        INT32 shift = msi_rest - msi_rhs;
        for ( INT32 i = BI2048_LIMBS - 1; i >= 0; i-- )
        {
            INT32 j = i - shift;
            b.m_Limbs[i] = (j >= 0) ? rhs.m_Limbs[j] : 0;
        }
        CFeBigInt2048 c = b.MulAbs(e);
        Sub(rest, rest, c);
        for ( INT32 i = msi_rest - msi_rhs; e > 0 && i < BI2048_LIMBS; i++ )
        {
            e += quot.m_Limbs[i];
            quot.m_Limbs[i] = (BASE_TYPE)e;
            BI2048_SHIFT_RIGHT_LIMB(e);
        }
        if ( msi_rest < BI2048_LIMBS - 1 )
        {
            msi_rest++;
        }
    }

    INT32 i = 0;
    while ( Compare(rest, rhs) >= 0 )
    {
        Sub(rest, rest, rhs);
        i++;
    }
    if ( i > 0 )
    {
        quot = quot.AddAbs(i);
    }

    if ( remain != NULL )
    {
        *remain = rest;
    }
    return quot;
}

UINT32 CFeBigInt2048::ModSmall(UINT32 n) const
{
    CALC_TYPE acc = 0;
    for ( INT32 i = BI2048_LIMBS - 1; i >= 0; --i )
    {
        acc <<= BI2048_BASE_SHIFT;
        acc += m_Limbs[i];
        acc = acc % n;
    }
    return (UINT32)acc;
}

VOID CFeBigInt2048::ShiftRight1()
{
    // logical shift right 2048-bit by 1 bit (LE limb)
    BASE_TYPE carry = 0;
    for ( INT32 i = BI2048_LIMBS - 1; i >= 0; --i )
    {
        BASE_TYPE newCarry = ((m_Limbs[i] & 1u) << 31);
        m_Limbs[i] = (m_Limbs[i] >> 1) | carry;
        carry = newCarry;
    }
}

INT32 CFeBigInt2048::SearchMSB() const
{
    for ( INT32 i = BI2048_LIMBS - 1; i >= 0; i-- )
    {
        if ( m_Limbs[i] != 0 )
        {
            INT32 b = (i + 1) * BI2048_BASE_SHIFT - 1;
            for ( BASE_TYPE m = 0x80000000; m > 0; m >>= 1 )
            {
                if ( (m_Limbs[i] & m) != 0 )
                {
                    return b;
                }
                b--;
            }
        }
    }
    return -1;
}


#if 0
VOID CFeBigInt2048::ToHex(CHAR8 * buf) const
{
    for ( INT32 i = 0; i < BI2048_LIMBS; i++ )
    {
        buf += sprintf(buf, "0x%0*x, ", BI2048_BASE_SIZE * 2, m_Limbs[i]);
    }
    *buf = '\0';
}
#endif


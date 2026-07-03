/* ========================================================================== */
/**
 * @file    FeBigInt512.cpp
 * @brief   512-bit BigInt class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "FeBigInt512.h"
#include "secure.h"


CFeBigInt512 CFeBigInt512::Zero((UINT32)0);
CFeBigInt512 CFeBigInt512::One((UINT32)1);
CFeBigInt512 CFeBigInt512::Two((UINT32)2);

CFeBigInt512::CFeBigInt512()
{
    Init();
}

CFeBigInt512::CFeBigInt512(UINT32 n)
{
    Init();
    m_Limbs[0] = (BASE_TYPE)n;
}

CFeBigInt512::CFeBigInt512(const UINT8 s[BI512_BYTES])
{
    fromBytesLE(s);
}

CFeBigInt512::~CFeBigInt512()
{
    Init();
}

VOID CFeBigInt512::Init()
{
    secure_zero(m_Limbs, sizeof(m_Limbs));
}

VOID CFeBigInt512::fromBytesLE(const UINT8 s[], SIZE_T size)
{
    SIZE_T n = (size / 4 < BI512_LIMBS) ? size / 4 : BI512_LIMBS;
    SIZE_T i;

    for ( i = 0; i < n; i++ )
    {
        m_Limbs[i] = s[i * 4] | (s[i * 4 + 1] << 8) | (s[i * 4 + 2] << 16) | (s[i * 4 + 3] << 24);
    }
    if ( i < BI512_LIMBS )
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
        for ( i++ ; i < BI512_LIMBS; i++ )
        {
            m_Limbs[i] = 0;
        }
    }
}

VOID CFeBigInt512::toBytesLE(UINT8 out[], SIZE_T size) const
{
    SIZE_T n = (size / 4 < BI512_LIMBS) ? size / 4 : BI512_LIMBS;
    SIZE_T i;

    for ( i = 0; i < n; i++ )
    {
        out[i * 4]     = (UINT8)m_Limbs[i];
        out[i * 4 + 1] = (UINT8)(m_Limbs[i] >> 8);
        out[i * 4 + 2] = (UINT8)(m_Limbs[i] >> 16);
        out[i * 4 + 3] = (UINT8)(m_Limbs[i] >> 24);
    }
    if ( i < BI512_LIMBS )
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

VOID CFeBigInt512::fromBytesBE(const UINT8 s[], SIZE_T size)
{
    INT32 remain = (INT32)size % 4;
    INT32 i;
    INT32 j;

    for ( i = (INT32)size - 4, j = 0; i >= remain && j < BI512_LIMBS; i -= 4, j++ )
    {
        m_Limbs[j] = s[i + 3] | (s[i + 2] << 8) | (s[i + 1] << 16) | (s[i] << 24);
    }
    if ( j < BI512_LIMBS )
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
        for ( j++ ; j < BI512_LIMBS; j++ )
        {
            m_Limbs[j] = 0;
        }
    }
}

VOID CFeBigInt512::toBytesBE(UINT8 out[], SIZE_T size) const
{
    INT32 remain = (INT32)size % 4;
    INT32 i;
    INT32 j;

    for ( i = (INT32)size - 4, j = 0; i >= remain && j < BI512_LIMBS; i -= 4, j++ )
    {
        out[i + 3] = (UINT8)(m_Limbs[j]      );
        out[i + 2] = (UINT8)(m_Limbs[j] >>  8);
        out[i + 1] = (UINT8)(m_Limbs[j] >> 16);
        out[i    ] = (UINT8)(m_Limbs[j] >> 24);
    }
    if ( j < BI512_LIMBS )
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


VOID CFeBigInt512::Add(CFeBigInt512 & out, const CFeBigInt512 & a, const CFeBigInt512 & b)
{
    CALC_TYPE c = 0;

    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        c += (CALC_TYPE)a.m_Limbs[i] + (CALC_TYPE)b.m_Limbs[i];
        out.m_Limbs[i] = (BASE_TYPE)c;
        BI512_SHIFT_RIGHT_LIMB(c);
    }
}

VOID CFeBigInt512::Sub(CFeBigInt512 & out, const CFeBigInt512 & a, const CFeBigInt512 & b)
{
    CALC_TYPE c = 0;

    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        c = (CALC_TYPE)a.m_Limbs[i] - (CALC_TYPE)b.m_Limbs[i] - c;
        out.m_Limbs[i] = (BASE_TYPE)c;
        BI512_SHIFT_RIGHT_CARRY(c);
    }
}

#if 0
VOID CFeBigInt512::Sub(FOLD_BUF & out, const CFeBigInt512 & a)
{
    CALC_TYPE c = 0;
    for ( INT32 i = 0; i < BI512_FOLD_SIZE; i++ )
    {
        c = (CALC_TYPE)out[i] - ((i < BI512_LIMBS) ? (CALC_TYPE)a.m_Limbs[i] : 0) - c;
        out[i] = (BASE_TYPE)c;
        BI512_SHIFT_RIGHT_CARRY(c);
    }
}
#endif

VOID CFeBigInt512::Mul(FOLD_BUF & out, const CFeBigInt512 & a, const CFeBigInt512 & b)
{
    FOLD_BUF buf;
    Expand(buf, a);
    Mul(out, buf, b);
    secure_zero(buf, sizeof(buf));
}

VOID CFeBigInt512::Mul(FOLD_BUF & buf, const FOLD_BUF & a, const CFeBigInt512 & b)
{
    secure_zero(buf, sizeof(FOLD_BUF));
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        CALC_TYPE c = 0;
        for ( INT32 j = 0; j <= BI512_LIMBS; j++ )
        {
            if ( i + j >= BI512_FOLD_SIZE )
            {
                break;
            }
            CALC_TYPE d = (j < BI512_LIMBS) ? b.m_Limbs[j] : 0;
            c += (CALC_TYPE)buf[i + j] + ((CALC_TYPE)a[i] * d);
            buf[i + j] = (BASE_TYPE)c;
            BI512_SHIFT_RIGHT_LIMB(c);
        }
    }
}

VOID CFeBigInt512::Expand(FOLD_BUF & buf, const CFeBigInt512 & a)
{
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        buf[i] = a.m_Limbs[i];
    }
    for ( INT32 i = BI512_LIMBS; i < BI512_FOLD_SIZE; i++ )
    {
        buf[i] = 0;
    }
}

VOID CFeBigInt512::Extract(CFeBigInt512 & out, const FOLD_BUF & buf)
{
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        out.m_Limbs[i] = buf[i];
    }
}

VOID CFeBigInt512::cmux(const CFeBigInt512 &other, BASE_TYPE mask) // constant-time
{
    // this = (mask ? other : this)
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        m_Limbs[i] ^= mask & (m_Limbs[i] ^ other.m_Limbs[i]);
    }
}

VOID CFeBigInt512::cswap(CFeBigInt512 &other, BASE_TYPE mask) // constant-time
{
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        BASE_TYPE tmp = (m_Limbs[i] ^ other.m_Limbs[i]) & mask;
        m_Limbs[i] ^= tmp;
        other.m_Limbs[i] ^= tmp;
    }
}

VOID CFeBigInt512::copy(const CFeBigInt512 & n)
{
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        m_Limbs[i] = n.m_Limbs[i];
    }
}

INT32 CFeBigInt512::Compare(const CFeBigInt512 & a, const CFeBigInt512 & b)
{
    INT32 ret = 0;

    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
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

BOOL CFeBigInt512::IsZero() const
{
    BASE_TYPE b = 0;
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        b |= m_Limbs[i];
    }
    return b ? FALSE : TRUE;
}

INT32 CFeBigInt512::GetBit(INT32 bit) const
{
    INT32 byte = (bit >> 5);
    BASE_TYPE mask = (1u << (bit & 31));
    return (m_Limbs[byte] & mask) != 0 ? 1 : 0;
}

INT32 CFeBigInt512::GreaterEqual(const FOLD_BUF & a, const CFeBigInt512 & b)
{
    CALC_TYPE d = 0;

    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        d = (CALC_TYPE)a[i] - (CALC_TYPE)b.m_Limbs[i] - d;
        BI512_SHIFT_RIGHT_CARRY(d);
    }
    for ( INT32 i = BI512_LIMBS; i < BI512_FOLD_SIZE; i++ )
    {
        d = (CALC_TYPE)a[i] - d;
        BI512_SHIFT_RIGHT_CARRY(d);
    }
    return (INT32)(d ^ 1); /* (d != 0) ? 1 : 0 */
}

VOID CFeBigInt512::Mod(CFeBigInt512 & out, const CFeBigInt512 & a, const CFeBigInt512 & b)
{
    FOLD_BUF buf;

    Expand(buf, a);
    Mod(buf, b);
    Extract(out, buf);
    secure_zero(buf, sizeof(buf));
}

VOID CFeBigInt512::Mod(FOLD_BUF & buf, const CFeBigInt512 & a)
{
    INT32 msi_rhs;
    INT32 msi_rest;
    FOLD_BUF buf2;

    for ( msi_rhs = BI512_LIMBS - 1; msi_rhs >= 0; msi_rhs-- )
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

    for ( msi_rest = BI512_FOLD_SIZE - 1; msi_rest >= 0; msi_rest-- )
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
                d <<= BI512_BASE_SHIFT;
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
        for ( INT32 i = 0; i < BI512_FOLD_SIZE; i++ )
        {
            INT32 j = i - shift;
            buf2[i] = (j < BI512_LIMBS && j >= 0) ? a.m_Limbs[j] : 0;
        }
        CALC_TYPE c1 = 0;
        CALC_TYPE c2 = 0;
        for ( INT32 i = 0; i < BI512_FOLD_SIZE; i++ )
        {
            c1 += (CALC_TYPE)buf2[i] * e;
            buf2[i] = (BASE_TYPE)c1;
            c2 = (CALC_TYPE)buf[i] - (CALC_TYPE)buf2[i] - c2;
            buf[i] = (BASE_TYPE)c2;
            BI512_SHIFT_RIGHT_LIMB(c1);
            BI512_SHIFT_RIGHT_CARRY(c2);
        }
        if ( msi_rest < BI512_FOLD_SIZE - 1 )
        {
            msi_rest++;
        }
    }

    while ( GreaterEqual(buf, a) )
    {
        CALC_TYPE c = 0;
        for ( INT32 i = 0; i < BI512_FOLD_SIZE; i++ )
        {
            c = (CALC_TYPE)buf[i] - (CALC_TYPE)((i < BI512_LIMBS) ? a.m_Limbs[i] : 0) - c;
            buf[i] = (BASE_TYPE)c;
            BI512_SHIFT_RIGHT_CARRY(c);
        }
    }
    secure_zero(buf2, sizeof(buf2));
}

#if 0
VOID CFeBigInt512::Neg(CFeBigInt512 & out, const CFeBigInt512 & a)
{
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        out.m_Limbs[i] = (BASE_TYPE)~a.m_Limbs[i];
    }

    CALC_TYPE c = 1;

    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        c += out.m_Limbs[i];
        out.m_Limbs[i] = (BASE_TYPE)c;
        BI512_SHIFT_RIGHT_LIMB(c);
    }
}

VOID CFeBigInt512::ShiftRight()
{
    CALC_TYPE c;
    CALC_TYPE carry = 0;
    for ( INT32 i = BI512_LIMBS - 1; i >= 0; i-- )
    {
        c = (CALC_TYPE)(m_Limbs[i] & 1) << (BI512_BASE_SHIFT - 1);
        m_Limbs[i] = (BASE_TYPE)((m_Limbs[i] >> 1) | carry);
        carry = c;
    }
}

BOOL CFeBigInt512::IsPlus() const
{
    return !(IsMinus() & IsZero());
}
#endif

#if 0
VOID CFeBigInt512::ToHex(CHAR8 * buf) const
{
    for ( INT32 i = 0; i < BI512_LIMBS; i++ )
    {
        buf += sprintf(buf, "0x%0*x, ", BI512_BASE_SIZE * 2, m_Limbs[i]);
    }
    *buf = '\0';
}
#endif


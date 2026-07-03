/* ========================================================================== */
/**
 * @file    FeBigInt.h
 * @brief   BigInt template class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_FEBIGINT_H_)
#define _FEBIGINT_H_

#include "BasicDefs.h"
#include "secure.h"

template<SIZE_T BITS>
class CFeBigInt
{
public:
    static constexpr SIZE_T BaseBytes = 4; /* 4 = dword */
    static constexpr SIZE_T CalcBytes = 8; /* 8 = qword */
    static constexpr SIZE_T BaseBits = 32;
    static constexpr SIZE_T CalcBits = 64;

    typedef UINT32  BASE_TYPE;
    typedef INT32   SBASE_TYPE;
    typedef UINT64  CALC_TYPE;
    typedef INT64   SCALC_TYPE;

    static constexpr SIZE_T IntBytes = BITS / 8;
    static constexpr SIZE_T Limbs = IntBytes / BaseBytes;
    static constexpr SIZE_T FoldSize = Limbs * 2 + 1;

    inline static VOID ShiftRightLimb(CALC_TYPE & c) { c >>= BaseBits; }
    inline static VOID ShiftRightBorrow(CALC_TYPE & b) { b = (b >> (CalcBits - 1)) & 1; }

public:
    CFeBigInt() { Init(); }
    CFeBigInt(UINT32 n) { Init(); m_Limbs[0] = (BASE_TYPE)n; }
    CFeBigInt(const UINT8 s[IntBytes]) { fromBytesLE(s); }
    CFeBigInt(const CFeBigInt<BITS> & n) { copy(n); }
    ~CFeBigInt() { Init(); }

    static VOID Add(CFeBigInt<BITS> & out, const CFeBigInt<BITS> & a, const CFeBigInt<BITS> & b)
    {
        CALC_TYPE c = 0;

        for ( INT32 i = 0; i < Limbs; i++ )
        {
            c += (CALC_TYPE)a.m_Limbs[i] + (CALC_TYPE)b.m_Limbs[i];
            out.m_Limbs[i] = (BASE_TYPE)c;
            ShiftRightLimb(c);
        }
    }

    static VOID Sub(CFeBigInt<BITS> & out, const CFeBigInt<BITS> & a, const CFeBigInt<BITS> & b)
    {
        CALC_TYPE c = 0;

        for ( INT32 i = 0; i < Limbs; i++ )
        {
            c = (CALC_TYPE)a.m_Limbs[i] - (CALC_TYPE)b.m_Limbs[i] - c;
            out.m_Limbs[i] = (BASE_TYPE)c;
            ShiftRightBorrow(c);
        }
    }

    static VOID Mod(CFeBigInt<BITS> & out, const CFeBigInt<BITS> & a, const CFeBigInt<BITS> & b)
    {
        FOLD_BUF buf;

        Expand(buf, a);
        Mod(buf, b);
        Extract(out, buf);
        secure_zero(buf, sizeof(buf));
    }

#if 0
    static VOID Neg(CFeBigInt<BITS> & out, const CFeBigInt<BITS> & a);
    {
        for ( INT32 i = 0; i < Limbs; i++ )
        {
            out.m_Limbs[i] = (BASE_TYPE)~a.m_Limbs[i];
        }

        CALC_TYPE c = 1;

        for ( INT32 i = 0; i < Limbs; i++ )
        {
            c += out.m_Limbs[i];
            out.m_Limbs[i] = (BASE_TYPE)c;
            ShiftRightLimb(c);
        }
    }

    VOID ShiftRight()
    {
        CALC_TYPE c;
        CALC_TYPE carry = 0;
        for ( INT32 i = Limbs - 1; i >= 0; i-- )
        {
            c = (CALC_TYPE)(m_Limbs[i] & 1) << (BaseBits - 1);
            m_Limbs[i] = (BASE_TYPE)((m_Limbs[i] >> 1) | carry);
            carry = c;
        }
    }
#endif

    INT32 GetBit(INT32 bit) const
    {
        INT32 byte = (bit >> 5);
        BASE_TYPE mask = (1u << (bit & 31));
        return (m_Limbs[byte] & mask) != 0 ? 1 : 0;
    }

    BOOL operator==(const CFeBigInt<BITS> & rhs) const { return Cmp(rhs) == 0; }
    BOOL operator!=(const CFeBigInt<BITS> & rhs) const { return Cmp(rhs) != 0; }
    BOOL operator>(const CFeBigInt<BITS> & rhs) const { return Cmp(rhs) > 0; }
    BOOL operator>=(const CFeBigInt<BITS> & rhs) const { return Cmp(rhs) >= 0; }
    BOOL operator<(const CFeBigInt<BITS> & rhs) const { return Cmp(rhs) < 0; }
    BOOL operator<=(const CFeBigInt<BITS> & rhs) const { return Cmp(rhs) <= 0; }

    BOOL operator==(INT32 rhs) const { return Cmp(rhs) == 0; }
    BOOL operator!=(INT32 rhs) const { return Cmp(rhs) != 0; }
    BOOL operator>(INT32 rhs) const { return Cmp(rhs) > 0; }
    BOOL operator>=(INT32 rhs) const { return Cmp(rhs) >= 0; }
    BOOL operator<(INT32 rhs) const { return Cmp(rhs) < 0; }
    BOOL operator<=(INT32 rhs) const { return Cmp(rhs) <= 0; }

    BOOL IsOdd() const { return (m_Limbs[0] & 1) != 0; }
    BOOL IsEven() const { return (m_Limbs[0] & 1) == 0; }

    BOOL IsMinus() const { return (m_Limbs[Limbs - 1] & ((BASE_TYPE)1 << (BaseBits - 1))) != 0; }

    BOOL IsZero() const
    {
        BASE_TYPE b = 0;
        for ( INT32 i = 0; i < Limbs; i++ )
        {
            b |= m_Limbs[i];
        }
        return b ? FALSE : TRUE;
    }

    // BOOL IsPlus() const { return !(IsMinus() & IsZero()); }

    VOID fromBytesLE(const UINT8 * s, SIZE_T size = IntBytes)
    {
        SIZE_T n = (size / 4 < Limbs) ? size / 4 : Limbs;
        SIZE_T i;

        for ( i = 0; i < n; i++ )
        {
            m_Limbs[i] = s[i * 4] | (s[i * 4 + 1] << 8) | (s[i * 4 + 2] << 16) | (s[i * 4 + 3] << 24);
        }
        if ( i < Limbs )
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
            for ( i++ ; i < Limbs; i++ )
            {
                m_Limbs[i] = 0;
            }
        }
    }

    VOID toBytesLE(UINT8 * out, SIZE_T size = IntBytes) const
    {
        SIZE_T n = (size / 4 < Limbs) ? size / 4 : Limbs;
        SIZE_T i;

        for ( i = 0; i < n; i++ )
        {
            out[i * 4]     = (UINT8)m_Limbs[i];
            out[i * 4 + 1] = (UINT8)(m_Limbs[i] >> 8);
            out[i * 4 + 2] = (UINT8)(m_Limbs[i] >> 16);
            out[i * 4 + 3] = (UINT8)(m_Limbs[i] >> 24);
        }
        if ( i < Limbs )
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

    VOID fromBytesBE(const UINT8 * s, SIZE_T size = IntBytes)
    {
        INT32 remain = (INT32)size % 4;
        INT32 i;
        INT32 j;

        for ( i = (INT32)size - 4, j = 0; i >= remain && j < Limbs; i -= 4, j++ )
        {
            m_Limbs[j] = s[i + 3] | (s[i + 2] << 8) | (s[i + 1] << 16) | (s[i] << 24);
        }
        if ( j < Limbs )
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
            for ( j++ ; j < Limbs; j++ )
            {
                m_Limbs[j] = 0;
            }
        }
    }

    VOID toBytesBE(UINT8 * out, SIZE_T size = IntBytes) const
    {
        INT32 remain = (INT32)size % 4;
        INT32 i;
        INT32 j;

        for ( i = (INT32)size - 4, j = 0; i >= remain && j < Limbs; i -= 4, j++ )
        {
            out[i + 3] = (UINT8)(m_Limbs[j]      );
            out[i + 2] = (UINT8)(m_Limbs[j] >>  8);
            out[i + 1] = (UINT8)(m_Limbs[j] >> 16);
            out[i    ] = (UINT8)(m_Limbs[j] >> 24);
        }
        if ( j < Limbs )
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

    VOID cmux(const CFeBigInt<BITS> & other, BASE_TYPE mask)
    {
        // this = (mask ? other : this)
        for ( INT32 i = 0; i < Limbs; i++ )
        {
            m_Limbs[i] ^= mask & (m_Limbs[i] ^ other.m_Limbs[i]);
        }
    }

    VOID cswap(CFeBigInt<BITS> & other, BASE_TYPE mask)
    {
        for ( INT32 i = 0; i < Limbs; i++ )
        {
            BASE_TYPE tmp = (m_Limbs[i] ^ other.m_Limbs[i]) & mask;
            m_Limbs[i] ^= tmp;
            other.m_Limbs[i] ^= tmp;
        }
    }

    VOID copy(const CFeBigInt<BITS> & n)
    {
        for ( INT32 i = 0; i < Limbs; i++ )
        {
            m_Limbs[i] = n.m_Limbs[i];
        }
    }

    static CFeBigInt Zero;      // 0
    static CFeBigInt One;       // 1
    static CFeBigInt Two;       // 2

#if 0
    VOID ToHexText(CHAR8 * buf) const;
    VOID ToHex(CHAR8 * buf) const;
    VOID ToText(CHAR8 * buf) const;
    VOID FromText(const CHAR8 * buf);
#endif

protected:
    typedef BASE_TYPE FOLD_BUF[FoldSize];

    INT32 Cmp(const CFeBigInt<BITS> & a) const { return Compare(*this, a); }

    static VOID Expand(FOLD_BUF & buf, const CFeBigInt<BITS> & a)
    {
        for ( INT32 i = 0; i < Limbs; i++ )
        {
            buf[i] = a.m_Limbs[i];
        }
        for ( INT32 i = Limbs; i < FoldSize; i++ )
        {
            buf[i] = 0;
        }
    }

    static VOID Extract(CFeBigInt<BITS> & out, const FOLD_BUF & buf)
    {
        for ( INT32 i = 0; i < Limbs; i++ )
        {
            out.m_Limbs[i] = buf[i];
        }
    }

    static VOID Sub(FOLD_BUF & out, const CFeBigInt<BITS> & a)
    {
        CALC_TYPE c = 0;
        for ( INT32 i = 0; i < FoldSize; i++ )
        {
            c = (CALC_TYPE)out[i] - ((i < Limbs) ? (CALC_TYPE)a.m_Limbs[i] : 0) - c;
            out[i] = (BASE_TYPE)c;
            ShiftRightBorrow(c);
        }
    }

    static VOID Mul(FOLD_BUF & out, const CFeBigInt<BITS> & a, const CFeBigInt<BITS> & b)
    {
        FOLD_BUF buf;
        Expand(buf, a);
        Mul(out, buf, b);
        secure_zero(buf, sizeof(buf));
    }

    static VOID Mul(FOLD_BUF & buf, const FOLD_BUF & a, const CFeBigInt<BITS> & b)
    {
        secure_zero(buf, sizeof(FOLD_BUF));
        for ( INT32 i = 0; i < Limbs; i++ )
        {
            CALC_TYPE c = 0;
            for ( INT32 j = 0; j <= Limbs; j++ )
            {
                if ( i + j >= FoldSize )
                {
                    break;
                }
                CALC_TYPE d = (j < Limbs) ? b.m_Limbs[j] : 0;
                c += (CALC_TYPE)buf[i + j] + ((CALC_TYPE)a[i] * d);
                buf[i + j] = (BASE_TYPE)c;
                ShiftRightLimb(c);
            }
        }
    }

    static VOID Mod(FOLD_BUF & buf, const CFeBigInt<BITS> & a)
    {
        INT32 msi_rhs;
        INT32 msi_rest;
        FOLD_BUF buf2;

        for ( msi_rhs = Limbs - 1; msi_rhs >= 0; msi_rhs-- )
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

        for ( msi_rest = FoldSize - 1; msi_rest >= 0; msi_rest-- )
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
                    d <<= BaseBits;
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
            for ( INT32 i = 0; i < FoldSize; i++ )
            {
                INT32 j = i - shift;
                buf2[i] = (j < Limbs && j >= 0) ? a.m_Limbs[j] : 0;
            }
            CALC_TYPE c1 = 0;
            CALC_TYPE c2 = 0;
            for ( INT32 i = 0; i < FoldSize; i++ )
            {
                c1 += (CALC_TYPE)buf2[i] * e;
                buf2[i] = (BASE_TYPE)c1;
                c2 = (CALC_TYPE)buf[i] - (CALC_TYPE)buf2[i] - c2;
                buf[i] = (BASE_TYPE)c2;
                ShiftRightLimb(c1);
                ShiftRightBorrow(c2);
            }
            if ( msi_rest < FoldSize - 1 )
            {
                msi_rest++;
            }
        }

        while ( GreaterEqual(buf, a) )
        {
            CALC_TYPE c = 0;
            for ( INT32 i = 0; i < FoldSize; i++ )
            {
                c = (CALC_TYPE)buf[i] - (CALC_TYPE)((i < Limbs) ? a.m_Limbs[i] : 0) - c;
                buf[i] = (BASE_TYPE)c;
                ShiftRightBorrow(c);
            }
        }
        secure_zero(buf2, sizeof(buf2));
    }

    static INT32 Compare(const CFeBigInt<BITS> & a, const CFeBigInt<BITS> & b)
    {
        INT32 ret = 0;

        for ( INT32 i = 0; i < Limbs; i++ )
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

    static INT32 GreaterEqual(const FOLD_BUF & a, const CFeBigInt<BITS> & b)
    {
        CALC_TYPE d = 0;

        for ( INT32 i = 0; i < Limbs; i++ )
        {
            d = (CALC_TYPE)a[i] - (CALC_TYPE)b.m_Limbs[i] - d;
            ShiftRightBorrow(d);
        }
        for ( INT32 i = Limbs; i < FoldSize; i++ )
        {
            d = (CALC_TYPE)a[i] - d;
            ShiftRightBorrow(d);
        }
        return (INT32)(d ^ 1); /* (d != 0) ? 1 : 0 */
    }

    VOID Init()
    {
        secure_zero(m_Limbs, sizeof(m_Limbs));
    }

    BASE_TYPE m_Limbs[Limbs];  // fixed precision version
};

template<SIZE_T BITS> CFeBigInt<BITS> CFeBigInt<BITS>::Zero(0u);      // 0
template<SIZE_T BITS> CFeBigInt<BITS> CFeBigInt<BITS>::One(1u);       // 1
template<SIZE_T BITS> CFeBigInt<BITS> CFeBigInt<BITS>::Two(2u);       // 2

#endif // _FEBIGINT_H_


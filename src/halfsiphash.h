/* ========================================================================== */
/**
 * @file    halfsiphash.h
 * @brief   HalfSipHash hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_HALFSIPHASH_H_)
#define _HALFSIPHASH_H_

#include "BasicDefs.h"
#include "secure.h"


/* helper macro */
#define ROTL32(a, b)  (UINT32)(((a) << (b)) | ((a) >> (32 - (b))))

template<SIZE_T C_ROUND, SIZE_T D_ROUND>
class CHalfSipHash
{
public:
    ~CHalfSipHash()
    {
        secure_zero(m_v, sizeof(m_v));
        secure_zero(m_k, sizeof(m_k));
    }

    VOID Initialize(const UINT8 key[8])
    {
        m_k[0] = LoadBytesLE32(key);
        m_k[1] = LoadBytesLE32(key + 4);
    }

    BOOL Hash(UINT8 * out, SIZE_T outlen, const UINT8 * in, SIZE_T inlen)
    {
        if ( outlen != 4 && outlen != 8 )
        {
            return FALSE;
        }

        m_v[0] = 0;
        m_v[1] = 0;
        m_v[2] = 0x6c796765u;
        m_v[3] = 0x74656462u;

        m_v[0] ^= m_k[0];
        m_v[1] ^= m_k[1];
        m_v[2] ^= m_k[0];
        m_v[3] ^= m_k[1];

        m_v[1] ^= (outlen == 8) ? 0xee : 0x00;

        UINT32 b = ((UINT32)inlen) << 24;

        while ( inlen >= 4 )
        {
            UINT32 m = LoadBytesLE32(in);
            m_v[3] ^= m;
            for ( INT32 i = 0; i < C_ROUND; i++ )
            {
                SipRound();
            }
            m_v[0] ^= m;
            in += 4;
            inlen -= 4;
        }
        b |= LoadBytesLE32(in, inlen);
        m_v[3] ^= b;

        for ( INT32 i = 0; i < C_ROUND; i++ )
        {
            SipRound();
        }

        m_v[0] ^= b;
        m_v[2] ^= (outlen == 8) ?  0xee : 0xff;

        for ( INT32 i = 0; i < D_ROUND; i++ )
        {
            SipRound();
        }

        StoreBytesLE32(out, m_v[1] ^ m_v[3]);

        if ( outlen == 4 )
        {
            return TRUE;
        }

        m_v[1] ^= 0xdd;

        for ( INT32 i = 0; i < D_ROUND; i++ )
        {
            SipRound();
        }

        StoreBytesLE32(out + 4, m_v[1] ^ m_v[3]);

        return TRUE;
    }

private:
    VOID SipRound()
    {
        m_v[0] += m_v[1];
        m_v[1] = ROTL32(m_v[1], 5);
        m_v[1] ^= m_v[0];
        m_v[0] = ROTL32(m_v[0], 16);
        m_v[2] += m_v[3];
        m_v[3] = ROTL32(m_v[3], 8);
        m_v[3] ^= m_v[2];
        m_v[0] += m_v[3];
        m_v[3] = ROTL32(m_v[3], 7);
        m_v[3] ^= m_v[0];
        m_v[2] += m_v[1];
        m_v[1] = ROTL32(m_v[1], 13);
        m_v[1] ^= m_v[2];
        m_v[2] = ROTL32(m_v[2], 16);
    }

    static UINT32 LoadBytesLE32(const UINT8 b[4])
    {
        return (UINT32)b[0] | ((UINT32)b[1] << 8) | ((UINT32)b[2] << 16) | ((UINT32)b[3] << 24);
    }

    static UINT32 LoadBytesLE32(const UINT8 b[], SIZE_T len)
    {
        UINT32 n = 0;

        for ( INT32 i = len - 1; i >= 0; i-- )
        {
            n <<= 8;
            n |= b[i];
        }
        return n;
    }

    static VOID StoreBytesLE32(UINT8 b[4], UINT32 n)
    {
        for ( INT32 i = 0; i < 4; i++ )
        {
            b[i] = (UINT8)n;
            n >>= 8;
        }
    }

    UINT32 m_v[4];
    UINT32 m_k[2];
};

class CHalfSipHash24 : public CHalfSipHash<2, 4> { };

#endif // #if !defined(_HALFSIPHASH_H_)


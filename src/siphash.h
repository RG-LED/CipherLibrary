/* ========================================================================== */
/**
 * @file    siphash.h
 * @brief   SipHash hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_SIPHASH_H_)
#define _SIPHASH_H_

#include "BasicDefs.h"
#include "secure.h"


/* helper macro */
#define ROTL64(a, b)  (UINT64)(((a) << (b)) | ((a) >> (64 - (b))))

template<SIZE_T C_ROUND, SIZE_T D_ROUND>
class CSipHash
{
public:
    ~CSipHash()
    {
        secure_zero(m_v, sizeof(m_v));
        secure_zero(m_k, sizeof(m_k));
    }

    VOID Initialize(const UINT8 key[16])
    {
        m_k[0] = LoadBytesLE64(key);
        m_k[1] = LoadBytesLE64(key + 8);
    }

    BOOL Hash(UINT8 * out, SIZE_T outlen, const UINT8 * in, SIZE_T inlen)
    {
        if ( outlen != 8 && outlen != 16 )
        {
            return FALSE;
        }

        m_v[0] = 0x736f6d6570736575llu;
        m_v[1] = 0x646f72616e646f6dllu;
        m_v[2] = 0x6c7967656e657261llu;
        m_v[3] = 0x7465646279746573llu;

        m_v[0] ^= m_k[0];
        m_v[1] ^= m_k[1];
        m_v[2] ^= m_k[0];
        m_v[3] ^= m_k[1];

        m_v[1] ^= (outlen == 16) ? 0xee : 0x00;

        UINT64 b = ((UINT64)inlen) << 56;

        while ( inlen >= 8 )
        {
            UINT64 m = LoadBytesLE64(in);
            m_v[3] ^= m;
            for ( INT32 i = 0; i < C_ROUND; i++ )
            {
                SipRound();
            }
            m_v[0] ^= m;
            in += 8;
            inlen -= 8;
        }
        b |= LoadBytesLE64(in, inlen);
        m_v[3] ^= b;

        for ( INT32 i = 0; i < C_ROUND; i++ )
        {
            SipRound();
        }

        m_v[0] ^= b;
        m_v[2] ^= (outlen == 16) ?  0xee : 0xff;

        for ( INT32 i = 0; i < D_ROUND; i++ )
        {
            SipRound();
        }

        StoreBytesLE64(out, m_v[0] ^ m_v[1] ^ m_v[2] ^ m_v[3]);

        if ( outlen == 8 )
        {
            return TRUE;
        }

        m_v[1] ^= 0xdd;

        for ( INT32 i = 0; i < D_ROUND; i++ )
        {
            SipRound();
        }

        StoreBytesLE64(out + 8, m_v[0] ^ m_v[1] ^ m_v[2] ^ m_v[3]);

        return TRUE;
    }

private:
    VOID SipRound()
    {
        m_v[0] += m_v[1];
        m_v[1] = ROTL64(m_v[1], 13);
        m_v[1] ^= m_v[0];
        m_v[0] = ROTL64(m_v[0], 32);
        m_v[2] += m_v[3];
        m_v[3] = ROTL64(m_v[3], 16);
        m_v[3] ^= m_v[2];
        m_v[0] += m_v[3];
        m_v[3] = ROTL64(m_v[3], 21);
        m_v[3] ^= m_v[0];
        m_v[2] += m_v[1];
        m_v[1] = ROTL64(m_v[1], 17);
        m_v[1] ^= m_v[2];
        m_v[2] = ROTL64(m_v[2], 32);
    }

    static UINT32 LoadBytesLE32(const UINT8 b[4])
    {
        return (UINT32)b[0] | ((UINT32)b[1] << 8) | ((UINT32)b[2] << 16) | ((UINT32)b[3] << 24);
    }

    static UINT64 LoadBytesLE64(const UINT8 b[8])
    {
        return (UINT64)LoadBytesLE32(b) | ((UINT64)LoadBytesLE32(b + 4) << 32);
    }

    static UINT64 LoadBytesLE64(const UINT8 b[], SIZE_T len)
    {
        UINT64 n = 0;

        for ( INT32 i = len - 1; i >= 0; i-- )
        {
            n <<= 8;
            n |= b[i];
        }
        return n;
    }

    static VOID StoreBytesLE64(UINT8 b[8], UINT64 n)
    {
        for ( INT32 i = 0; i < 8; i++ )
        {
            b[i] = (UINT8)n;
            n >>= 8;
        }
    }

    UINT64 m_v[4];
    UINT64 m_k[2];
};

class CSipHash24 : public CSipHash<2, 4> { };

#endif // #if !defined(_SIPHASH_H_)


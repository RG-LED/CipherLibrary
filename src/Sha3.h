/* ========================================================================== */
/**
 * @file    sha3.h
 * @brief   SHA3 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_SHA3_H_)
#define _SHA3_H_

#include "secure.h"

#define SHA3_DSBYTE     0x06 /* domain separation for SHA3 */

#define ROL64(x, n) (((x) << ((n) & 63)) | ((x) >> (64 - ((n) & 63))))

template <SIZE_T RATE, SIZE_T OUTLEN>
class CSha3base
{
public:
    CSha3base() { Initialize(); }
    ~CSha3base() { Initialize(); }

    VOID GetHash(VOID * out, const VOID * in, SIZE_T inlen)
    { Initialize(); Update(in, inlen); GetHash(out); }

    VOID Initialize() { secure_zero(m_A, sizeof(m_A)); secure_zero(m_Q, sizeof(m_Q)); m_Qlen = 0; }
    VOID Finish(UINT8 * out) { Finalize(); Squeeze(out, OUTLEN); }

    VOID Update(const UINT8 * in, SIZE_T inlen)
    {
        SIZE_T i;
        /* If there is buffered data, fill to a block first */
        if ( m_Qlen )
        {
            SIZE_T take = RATE - m_Qlen;
            if ( take > inlen )
            {
                take = inlen;
            }
            memcpy(m_Q + m_Qlen, in, take);
            m_Qlen += take;
            in += take;
            inlen -= take;
            if ( m_Qlen < RATE )
            {
                return;
            }
            /* XOR the block into state and permute */
            for ( i = 0; i < RATE / 8; i++ )
            {
                m_A[i] ^= Load64le(m_Q + 8 * i);
            }
            Keccakf1600();
            m_Qlen = 0;
        }
        /* Absorb full blocks directly from input */
        while ( inlen >= RATE )
        {
            for ( i = 0; i < RATE / 8; i++ )
            {
                m_A[i] ^= Load64le(in + 8 * i);
            }
            Keccakf1600();
            in += RATE;
            inlen -= RATE;
        }
        /* Buffer remaining */
        if ( inlen )
        {
            memcpy(m_Q, in, inlen);
            m_Qlen = inlen;
        }
    }

    const SIZE_T OutputSize = OUTLEN;

protected:
    VOID Keccakf1600()
    {
        /* ======== Keccak-f[1600] constants ======== */
        static const UINT64 KECCAKF_ROUND_CONST[24] = {
            0x0000000000000001ULL, 0x0000000000008082ULL,
            0x800000000000808aULL, 0x8000000080008000ULL,
            0x000000000000808bULL, 0x0000000080000001ULL,
            0x8000000080008081ULL, 0x8000000000008009ULL,
            0x000000000000008aULL, 0x0000000000000088ULL,
            0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL,
            0x8000000000008089ULL, 0x8000000000008003ULL,
            0x8000000000008002ULL, 0x8000000000000080ULL,
            0x000000000000800aULL, 0x800000008000000aULL,
            0x8000000080008081ULL, 0x8000000000008080ULL,
            0x0000000080000001ULL, 0x8000000080008008ULL
        };

        static const INT32 keccakf_rotc[24] = {
             1,  3,  6, 10, 15, 21, 28, 36,
            45, 55,  2, 14, 27, 41, 56,  8,
            25, 43, 62, 18, 39, 61, 20, 44
        };
        static const INT32 keccakf_piln[24] = {
            10,  7, 11, 17, 18,  3,  5, 16,
             8, 21, 24,  4, 15, 23, 19, 13,
            12,  2, 20, 14, 22,  9,  6,  1
        };

        for ( INT32 round = 0; round < 24; round++ )
        {
            UINT64 bc[5];
            for ( INT32 i = 0; i < 5; i++ )
            {
                bc[i] = m_A[i] ^ m_A[i + 5] ^ m_A[i + 10] ^ m_A[i + 15] ^ m_A[i + 20];
            }
            for ( INT32 i = 0; i < 5; i++ )
            {
                UINT64 d = bc[(i + 4) % 5] ^ ROL64(bc[(i + 1) % 5], 1);
                for ( INT32 j = 0; j < 25; j += 5 )
                {
                    m_A[j + i] ^= d;
                }
            }

            UINT64 t = m_A[1];
            for ( INT32 i = 0; i < 24; i++ )
            {
                INT32 j = keccakf_piln[i];
                UINT64 tmp = m_A[j];
                m_A[j] = ROL64(t, keccakf_rotc[i]);
                t = tmp;
            }

            for ( INT32 j = 0; j < 25; j += 5 )
            {
                UINT64 b0 = m_A[j+0];
                UINT64 b1 = m_A[j+1];
                UINT64 b2 = m_A[j+2];
                UINT64 b3 = m_A[j+3];
                UINT64 b4 = m_A[j+4];
                m_A[j+0] = b0 ^ ((~b1) & b2);
                m_A[j+1] = b1 ^ ((~b2) & b3);
                m_A[j+2] = b2 ^ ((~b3) & b4);
                m_A[j+3] = b3 ^ ((~b4) & b0);
                m_A[j+4] = b4 ^ ((~b0) & b1);
            }

            m_A[0] ^= KECCAKF_ROUND_CONST[round];
        }
    }

    VOID Finalize()
    {
        /* domain separation suffix (0x06 for SHA3), then pad10*1 (0x80 at block end) */
        m_Q[m_Qlen++] = SHA3_DSBYTE;
        while ( m_Qlen < RATE )
        {
            m_Q[m_Qlen++] = 0;
        }
        m_Q[RATE - 1] ^= 0x80; /* final bit 1 */
        for ( SIZE_T i = 0; i < RATE / 8; i++ )
        {
            m_A[i] ^= Load64le(m_Q + 8 * i);
        }
        Keccakf1600();
        m_Qlen = 0; /* ready to squeeze */
    }

    VOID Squeeze(UINT8 * out, SIZE_T outlen)
    {
        while ( outlen )
        {
            UINT8 buf[RATE];
            for ( SIZE_T i = 0; i < RATE / 8; i++ )
            {
                Store64le(buf + 8 * i, m_A[i]);
            }
            SIZE_T take = (outlen < RATE) ? outlen : RATE;
            memcpy(out, buf, take);
            out += take;
            outlen -= take;
            if (outlen == 0)
            {
                break;
            }
            Keccakf1600();
        }
    }

    UINT64 m_A[25];         /* 1600-bit state */
    UINT8  m_Q[RATE];       /* partial block buffer (rate bytes) */
    SIZE_T m_Qlen;          /* buffered bytes */

    static UINT64 Load64le(const UINT8 * p)
    {
        UINT64 v = 0;
        for (INT32 i = 0; i < 8; i++)
        {
            v |= (UINT64)p[i] << (8 * i);
        }
        return v;
    }

    static VOID Store64le(UINT8 * p, UINT64 v)
    {
        for (INT32 i = 0; i < 8; i++)
        {
            p[i] = (UINT8)(v >> (8 * i));
        }
    }
};

class CSha3_224 : public CSha3base<144, 28> { };
class CSha3_256 : public CSha3base<136, 32> { };
class CSha3_384 : public CSha3base<104, 48> { };
class CSha3_512 : public CSha3base< 72, 64> { };

#endif // _SHA3_H_


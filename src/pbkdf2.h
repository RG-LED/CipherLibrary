/* ========================================================================== */
/**
 * @file    pbkdf2.h
 * @brief   PBKDF2 key derivation class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_PBKDF2_H_)
#define _PBKDF2_H_

#include "BasicDefs.h"

template<typename HASH>
class CPbkdf2
{
public:
    static constexpr SIZE_T HashSize = HASH::OutputSize;

    VOID Prepare(const UINT8 key[], SIZE_T len)
    {
        UINT8 k_pad[(HashSize > 32) ? 128 : 64] = { 0 }; // work area of 64 bytes

        // 1. key
        if ( len > sizeof(k_pad) )
        {
            m_iHash.Initialize();
            m_iHash.Update(key, len);
            m_iHash.Finish(k_pad); // store it to first HashSize bytes, the rests are 0x00
        }
        else
        {
            memcpy(k_pad, key, len);
        }

        // 2. ipad
        m_iHash.Initialize();
        for ( INT32 i = 0; i < sizeof(k_pad); i++ )
        {
            k_pad[i] ^= 0x36; // make it ipad temporarily
        }
        m_iHash.Update(k_pad, sizeof(k_pad));

        // 3. opad
        m_oHash.Initialize();
        for ( INT32 i = 0; i < sizeof(k_pad); i++ )
        {
            k_pad[i] ^= (0x36 ^ 0x5c); // switch it from ipad to opad
        }
        m_oHash.Update(k_pad, sizeof(k_pad));
        secure_zero(k_pad, sizeof(k_pad));
    }

    VOID Iteration(const UINT8 * salt, SIZE_T len, UINT32 iter, UINT32 index, UINT8 * out)
    {
        UINT8 digest[HashSize];
        UINT8 acc[HashSize] = { 0 };

        // --- 1st round (U_1) ---
        // Message = Salt + BlockIndex (4byte, BigEndian)
        HASH temp = m_iHash; 
        temp.Update(salt, len);

        UINT8 be_idx[4];
        be_idx[0] = (UINT8)(index >> 24);
        be_idx[1] = (UINT8)(index >> 16);
        be_idx[2] = (UINT8)(index >> 8);
        be_idx[3] = (UINT8)(index);

        temp.Update(be_idx, 4);
        temp.Finish(digest); // inner hash complete

        temp = m_oHash;
        temp.Update(digest, HashSize);
        temp.Finish(digest); // outer hash complete

        memcpy(acc, digest, HashSize);

        // --- 2nd round and after (U_2 to U_n) ---
        for ( UINT32 i = 1; i < iter; i++ )
        {
            // internal hash: SHA256( (Key^ipad) + digest )
            temp = m_iHash;
            temp.Update(digest, HashSize);
            temp.Finish(digest);

            // external hash: SHA256( (Key^opad) + inner_result )
            temp = m_oHash;
            temp.Update(digest, HashSize);
            temp.Finish(digest); // U_i

            // combine result by XOR: acc ^= U_i
            for ( INT32 j = 0; j < HashSize; j++ )
            {
                acc[j] ^= digest[j];
            }
        }

        // store final result
        memcpy(out, acc, HashSize);
        secure_zero(digest, sizeof(digest));
        secure_zero(acc, sizeof(acc));
    }

private:
    HASH m_iHash;
    HASH m_oHash;
};

#endif // #if !defined(_PBKDF2_H_)


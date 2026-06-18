/* ========================================================================== */
/**
 * @file    pbkdf2.cpp
 * @brief   PBKDF2 key derivation class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "pbkdf2.h"

VOID CPbkdf2::Prepare(const UINT8 key[], SIZE_T len)
{
    UINT8 k_pad[64] = { 0 }; // work area of 64 bytes

    // 1. key
    if ( len > 64 )
    {
        m_iSha.Update(key, len);
        m_iSha.Finish(k_pad); // store it to first 32 bytes, the rests are 0x00
    }
    else
    {
        memcpy(k_pad, key, len);
    }

    // 2. ipad
    m_iSha.Initialize();
    for ( INT32 i = 0; i < 64; i++ )
    {
        k_pad[i] ^= 0x36; // make it ipad temporarily
    }
    m_iSha.Update(k_pad, 64);

    // 3. opad
    m_oSha.Initialize();
    for ( INT32 i = 0; i < 64; i++ )
    {
        k_pad[i] ^= (0x36 ^ 0x5c); // switch it from ipad to opad
    }
    m_oSha.Update(k_pad, 64);
}

VOID CPbkdf2::Iteration(const UINT8 * salt, SIZE_T len, UINT32 iter, UINT32 index, UINT8 * out)
{
    UINT8 digest[32];
    UINT8 acc[32] = { 0 };

    // --- 1st round (U_1) ---
    // Message = Salt + BlockIndex (4byte, BigEndian)
    CSha256 temp = m_iSha; 
    temp.Update(salt, len);

    UINT8 be_idx[4];
    be_idx[0] = (UINT8)(index >> 24);
    be_idx[1] = (UINT8)(index >> 16);
    be_idx[2] = (UINT8)(index >> 8);
    be_idx[3] = (UINT8)(index);

    temp.Update(be_idx, 4);
    temp.Finish(digest); // inner hash complete

    temp = m_oSha;
    temp.Update(digest, 32);
    temp.Finish(digest); // outer hash complete

    memcpy(acc, digest, 32);

    // --- 2nd round and after (U_2 to U_n) ---
    for ( UINT32 i = 1; i < iter; i++ )
    {
        // internal hash: SHA256( (Key^ipad) + digest )
        temp = m_iSha;
        temp.Update(digest, 32);
        temp.Finish(digest);

        // external hash: SHA256( (Key^opad) + inner_result )
        temp = m_oSha;
        temp.Update(digest, 32);
        temp.Finish(digest); // U_i

        // combine result by XOR: acc ^= U_i
        for ( INT32 j = 0; j < 32; j++ )
        {
            acc[j] ^= digest[j];
        }
    }

    // store final result
    memcpy(out, acc, 32);
}


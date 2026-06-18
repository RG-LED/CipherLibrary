/* ========================================================================== */
/**
 * @file    ghash.h
 * @brief   GHASH hash class for AES-GCM
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_GHASH_H_)
#define _GHASH_H_

#include "gf128be.h"

class CGHash
{
public:
    VOID Init(const CGf128BE & h)
    {
        m_H = h;
        m_Y.Zero();

        CGf128BE::SetH(h);
    }

    VOID UpdateBlock(const UINT8 block[16])
    {
        CGf128BE x;
        x.LoadBE(block);

        m_Y.Xor(x);
        m_Y.MulH();
    }

    VOID Final(UINT64 aad_bits, UINT64 c_bits)
    {
        UINT8 len_block[16];
        for ( INT32 i = 0; i < 8; i++ )
        {
            len_block[i    ] = (UINT8)(aad_bits >> ((7 - i) * 8));
            len_block[i + 8] = (UINT8)(c_bits   >> ((7 - i) * 8));
        }
        UpdateBlock(len_block);
    }

    VOID Get(UINT8 out[16]) const { m_Y.StoreBE(out); }

private:
    CGf128BE m_H;   // AES(K, 0^128)
    CGf128BE m_Y;   // accumulator
};

#endif // _GHASH_H_


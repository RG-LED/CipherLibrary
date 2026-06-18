/* ========================================================================== */
/**
 * @file    polyval.h
 * @brief   POLYVAL hash class for AES-GCM-SIV
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_POLYVAL_H_)
#define _POLYVAL_H_

#include "gf128le.h"

class CPolyval
{
public:
    VOID Init(const CGf128LE & h)
    {
        m_H = h;
        m_Y.Zero();

        CGf128LE::SetH(h);
    }

    VOID UpdateBlock(const UINT8 block[16])
    {
        CGf128LE x;
        x.LoadLE(block);

        m_Y.Xor(x);
        m_Y.MulH();
    }

    VOID Final(UINT64 aad_bits, UINT64 c_bits)
    {
        UINT8 len_block[16];
        for ( INT32 i = 0; i < 8; i++ )
        {
            len_block[i    ] = (UINT8)(aad_bits >> (i * 8));
            len_block[i + 8] = (UINT8)(c_bits   >> (i * 8));
        }
        UpdateBlock(len_block);
    }

    VOID Get(UINT8 out[16]) const { m_Y.StoreLE(out); }
    const CGf128LE & Value() const { return m_Y; }

private:
    CGf128LE m_H;   // AES(K, 0^128)
    CGf128LE m_Y;   // accumulator
};

#endif // _POLYVAL_H_


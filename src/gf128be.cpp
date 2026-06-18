/* ========================================================================== */
/**
 * @file    gf128be.cpp
 * @brief   Galois field number class for GHASH of AES-GCM
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "gf128be.h"

static const Gf128BE _R = {
    0x00000000,
    0x00000000,
    0x00000000,
    0xe1000000
};

CGf128BE CGf128BE::R(_R);
CGf128BE CGf128BE::hTable[16];

CGf128BE::CGf128BE(const Gf128BE & v)
{
    for ( INT32 i = 0; i < GF128BE_LIMBS; i++ )
    {
        limbs[i] = v.limbs[i];
    }
}

VOID CGf128BE::Shr1()
{
    LIMB_TYPE carry = 0;
    for ( INT32 i = GF128BE_LIMBS - 1; i >= 0; i-- )
    {
        LIMB_TYPE c = ((limbs[i] & 1u) << 31);
        limbs[i] = (limbs[i] >> 1) | carry;
        carry = c;
    }
}

VOID CGf128BE::Xor(const CGf128BE & a)
{
    for ( INT32 i = 0; i < GF128BE_LIMBS; i++ )
    {
        limbs[i] ^= a.limbs[i];
    }
}

VOID CGf128BE::Mul(const CGf128BE & a)
{
    CGf128BE n(*this);
    Zero();
    for ( INT32 i = GF128BE_LIMBS - 1; i >= 0; i-- )
    {
        for ( INT32 bit = 31; bit >= 0; bit-- )
        {
            if ( (a.limbs[i] & (1u << bit)) != 0 )
            {
                Xor(n);
            }
            BOOL lsb = ((n.limbs[0] & 1) != 0);
            n. Shr1();
            if ( lsb )
            {
                n.Xor(R);
            }
        }
    }
}

VOID CGf128BE::SetH(const CGf128BE & h)
{
    hTable[0].Zero();
    hTable[8] = h; // start at 8

    // make each element in the order 8, 4, 2, 1, using Shr1 & Xor(R)
    for ( INT32 j = 4; j >= 1; j >>= 1 )
    {
        hTable[j] = hTable[j * 2];
        BOOL lsb = ((hTable[j].limbs[0] & 1) != 0);
        hTable[j].Shr1();
        if ( lsb )
        {
            hTable[j].Xor(R);
        }
    }
    // make remaining (3, 5, 6, 7...) by XOR combination
    for ( INT32 i = 3; i < 16; i++ )
    {
        if ( (i != 4) && (i != 8) )
        { // not yet calculated
            hTable[i] = hTable[i & (i - 1)]; // nearest element calculated
            hTable[i].Xor(hTable[i & -i]);   // add value of last 1 bit
        }
    }
}

VOID CGf128BE::MulH()
{
    CGf128BE tmp(*this);
    Zero();

    for ( INT32 i = 0; i < GF128BE_LIMBS; i++ )
    {
        for ( INT32 nibble = 0; nibble < 8; nibble++ )
        {
            INT32 idx = (tmp.limbs[i] >> (nibble * 4)) & 0x0f;
            for ( INT32 k = 0; k < 4; k++ )
            {
                BOOL lsb = ((limbs[0] & 1) != 0);
                Shr1();
                if ( lsb )
                {
                    Xor(R);
                }
            }

            Xor(hTable[idx]);
        }
    }
}

VOID CGf128BE::LoadBE(const UINT8 b[])
{
    const UINT8 * p = b;
    for ( INT32 i = 3; i >= 0; i-- )
    {
        limbs[i] = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
        p += 4;
    }
}

VOID CGf128BE::StoreBE(UINT8 b[]) const
{
    UINT8 * p = b;
    for ( INT32 i = 3; i >= 0; i-- )
    {
        p[0] = (UINT8)(limbs[i] >> 24);
        p[1] = (UINT8)(limbs[i] >> 16);
        p[2] = (UINT8)(limbs[i] >> 8);
        p[3] = (UINT8)(limbs[i]);
        p += 4;
    }
}


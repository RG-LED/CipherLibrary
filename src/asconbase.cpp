/* ========================================================================== */
/**
 * @file    asconbase.cpp
 * @brief   Ascon base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asconbase.h"
#include "secure.h"

CAsconBase::CAsconBase()
{
    secure_zero(m_state, sizeof(m_state));
}

CAsconBase::~CAsconBase()
{
    secure_zero(m_state, sizeof(m_state));
}


// helper macro of bit rotation (right)
#define ROTR64(x, n)    (((x) >> (n)) | ((x) << (64 - (n))))

VOID CAsconBase::Permutation(INT32 rounds)
{
    // constants for 12 rounds (value to XOR with x2)
    static const UINT8 ROUND_CONSTANTS[12] = {
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
    };

    // get start index according to rounds parameter
    // start at 0 for 12 rounds, 6 for 6 rounds
    INT32 start_round = 12 - rounds;

    for ( INT32 r = start_round; r < 12; r++ )
    {
        // --- 1. add constant ---
        m_state[2] ^= (UINT64)ROUND_CONSTANTS[r];

        // --- 2. substitution (S-box) ---
        UINT64 x0 = m_state[0];
        UINT64 x1 = m_state[1];
        UINT64 x2 = m_state[2];
        UINT64 x3 = m_state[3];
        UINT64 x4 = m_state[4];

        // mix previous result
        x0 ^= x4;
        x4 ^= x3;
        x2 ^= x1;

        // logical operation of bit slice S-box
        UINT64 t0 = ~x0 & x1;
        UINT64 t1 = ~x1 & x2;
        UINT64 t2 = ~x2 & x3;
        UINT64 t3 = ~x3 & x4;
        UINT64 t4 = ~x4 & x0;

        x0 ^= t1;
        x1 ^= t2;
        x2 ^= t3;
        x3 ^= t4;
        x4 ^= t0;

        // mixture of after process
        x1 ^= x0;
        x0 ^= x4;
        x3 ^= x2;
        x2 = ~x2; // invert x2 here

        // --- 3. linear diffusion layer ---
        m_state[0] = x0 ^ ROTR64(x0, 19) ^ ROTR64(x0, 28);
        m_state[1] = x1 ^ ROTR64(x1, 61) ^ ROTR64(x1, 39);
        m_state[2] = x2 ^ ROTR64(x2,  1) ^ ROTR64(x2,  6);
        m_state[3] = x3 ^ ROTR64(x3, 10) ^ ROTR64(x3, 17);
        m_state[4] = x4 ^ ROTR64(x4,  7) ^ ROTR64(x4, 41);
    }
}


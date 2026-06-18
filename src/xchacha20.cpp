/* ========================================================================== */
/**
 * @file    xchacha20.cpp
 * @brief   XChaCha20 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "xchacha20.h"

#if SUPPORT_RESEED
VOID CXChacha20::Initialize(const UINT8 seed32[32], const UINT8 nonce24[24], UINT32 counter, UINT64 reseed_interval_blocks)
#else
VOID CXChacha20::Initialize(const UINT8 seed32[32], const UINT8 nonce24[24], UINT32 counter)
#endif
{
    UINT32 w[16];
    w[0] = 0x61707865;
    w[1] = 0x3320646e;
    w[2] = 0x79622d32;
    w[3] = 0x6b206574;
    for ( INT32 i = 0; i < 8; i++ )
    {
        w[i + 4] = Load32(&seed32[i * 4]);
    }
    for ( INT32 i = 0; i < 4; i++ )
    {
        w[i + 12] = Load32(&nonce24[i * 4]);
    }

    RunChaChaRounds(w);

    m_Key[0] = w[0];  m_Key[1] = w[1];  m_Key[2] = w[2];  m_Key[3] = w[3];
    m_Key[4] = w[12]; m_Key[5] = w[13]; m_Key[6] = w[14]; m_Key[7] = w[15];

    m_Nonce[0] = 0;
    m_Nonce[1] = Load32(nonce24 + 16);
    m_Nonce[2] = Load32(nonce24 + 20);

    m_Counter   = counter;
    m_Avail     = 0;
#if SUPPORT_RESEED
    m_BlocksOut = 0;
    m_ReseedIntervalBlocks = reseed_interval_blocks;
#endif
}


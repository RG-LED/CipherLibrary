/* ========================================================================== */
/**
 * @file    blake2s.h
 * @brief   BLAKE2s hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_BLAKE2S_H_)
#define _BLAKE2S_H_

#include "BasicDefs.h"

class CBlake2s
{
public:
    static constexpr SIZE_T BlockSize = 64;
    static constexpr SIZE_T OutputSize = 32;

    CBlake2s();
    ~CBlake2s();

    VOID Initialize(const UINT8 * key = NULL, SIZE_T keylen = 0);
    VOID Update(const VOID * in, SIZE_T inlen);
    VOID Finish(UINT8 out[32]);

private:
    VOID Compress(const UINT8 block[64], INT32 is_last);
    VOID Clear();
    UINT32 m_H[8];
    UINT32 m_T[2];
    UINT32 m_F[2];
    UINT8  m_Buf[BlockSize];
    SIZE_T m_BufLen;
    static const UINT8 m_SIGMA[10][16];
};

#endif // !defined(_BLAKE2S_H_)


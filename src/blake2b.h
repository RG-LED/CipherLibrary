/* ========================================================================== */
/**
 * @file    blake2b.h
 * @brief   BLAKE2b hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

/* blake2b.h - BLAKE2b
 */
#if !defined(_BLAKE2B_H_)
#define _BLAKE2B_H_

#include "BasicDefs.h"

class CBlake2b
{
public:
    static constexpr SIZE_T BlockSize = 128;
    static constexpr SIZE_T OutputSize = 64;

    CBlake2b();
    ~CBlake2b();

    VOID Initialize(const UINT8 * key = NULL, SIZE_T keylen = 0);
    VOID Update(const VOID * in, SIZE_T inlen);
    VOID Finish(UINT8 out[64]);

private:
    VOID Compress(const UINT8 block[128], INT32 is_last);
    VOID Clear();
    UINT64 m_H[8];
    UINT64 m_T[2];
    UINT64 m_F[2];
    UINT8  m_Buf[BlockSize];
    SIZE_T m_BufLen;
    static const UINT8 m_SIGMA[12][16];
};

#endif // !defined(_BLAKE2B_H_)


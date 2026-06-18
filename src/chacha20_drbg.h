/* ========================================================================== */
/**
 * @file    chacha20_drbg.h
 * @brief   ChaCha20 random generator class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_CHACHA20_DRBG_H_)
#define _CHACHA20_DRBG_H_

#include "chacha20.h"

class CChacha20Drbg
{
public:
    CChacha20Drbg();
    ~CChacha20Drbg();
    VOID Initialize(const UINT8 seed[32]);
    VOID Fill(VOID * out, SIZE_T outlen);

private:
    VOID Clear();
    VOID Refill();

    CChacha20 m_Chacha20;
    UINT64 m_Counter;    // 64-bit block counter
};

#endif // #if !defined(_CHACHA20_DRBG_H_)


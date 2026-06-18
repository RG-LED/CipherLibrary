/* ========================================================================== */
/**
 * @file    shakebase.h
 * @brief   SHAKE128/256 hash base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_SHAKEBASE_H_)
#define _SHAKEBASE_H_

#include "BasicDefs.h"

#define SHAKE128_RATE   168  /* 1344 bits */
#define SHAKE256_RATE   136  /* 1088 bits */
#define MAX_SHAKE_RATE  SHAKE128_RATE
#define SHAKE_DSBYTE    0x1F /* domain separation for SHAKE */

class CShakeBase
{
public:
    CShakeBase();
    ~CShakeBase();

    VOID Shake(UINT8 * out, SIZE_T outlen, const UINT8 * in, SIZE_T inlen);

    VOID Clear();
    VOID Absorb(const UINT8 * in, SIZE_T inlen);
    VOID Finish();
    VOID Squeeze(UINT8 * out, SIZE_T outlen);

protected:
    VOID Keccakf1600();

    UINT64 m_A[25];             /* 1600-bit state */
    UINT8  m_Q[MAX_SHAKE_RATE]; /* partial block buffer (rate bytes) */
    SIZE_T m_Qlen;              /* buffered bytes */
    SIZE_T m_rate;

    static UINT64 Load64le(const UINT8 * p);
    static VOID Store64le(UINT8 * p, UINT64 v);
};

#endif // _SHAKEBASE_H_


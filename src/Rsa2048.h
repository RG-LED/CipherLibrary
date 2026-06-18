/* ========================================================================== */
/**
 * @file    Rsa2048.h
 * @brief   2048-bit RSA signature class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_RSA2048_H_)
#define _RSA2048_H_

#include "RsaBigInt2048.h"

struct CRsaKey2048Pub {
    CRsaBigInt2048  N;     // modulus
    UINT32          e;     // public exponent (65537)
    CRsaMontCtx2048 montN; // mont context for N
};

struct CRsaKey2048Priv {
    // private CRT parameters
    CRsaBigInt2048 p;
    CRsaBigInt2048 q;
    CRsaBigInt2048 dp;
    CRsaBigInt2048 dq;     // dp = d mod (p-1), dq = d mod (q-1)
    CRsaBigInt2048 qInv;   // qInv = q^{-1} mod p

    // mont context for CRT
    CRsaMontCtx2048 montP;
    CRsaMontCtx2048 montQ;
};

struct CRsaKey2048 {
    CRsaKey2048Pub  pub;
    CRsaKey2048Priv priv;
};

// ---- API ----

// 1) key generation (RSA-2048, e=65537, RSASSA-PSS)
BOOL RsaGenerate2048(CRsaKey2048 & key, INT32 mr_rounds = 48);

// 2) signature (RSASSA-PSS, SHA-256, saltLen=32)
BOOL RsaSignPSS_SHA256(const CRsaKey2048& key,
                       const UINT8 * msg, SIZE_T msgLen,
                       UINT8 sig[256], UINT32 saltLen = 32);

// 3) verification (RSASSA-PSS, SHA-256, saltLen=32)
BOOL RsaVerifyPSS_SHA256(const CRsaKey2048Pub& pub,
                         const UINT8 * msg, SIZE_T msgLen,
                         const UINT8 sig[256], UINT32 saltLen = 32);

#endif // _RSA2048_H_


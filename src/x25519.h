/* ========================================================================== */
/**
 * @file    x25519.h
 * @brief   X25519 key exchange class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_X25519_H_)
#define _X25519_H_

#include "fe25519.h"

class CX25519
{
public:
    static VOID PrivateKeyToPublicKey(UINT8 pub[32], const UINT8 priv[32]) { ScalarMult(pub, priv, BasePoint); }
    static VOID GetSharedSecret(UINT8 secret[32], const UINT8 priv[32], const UINT8 pub[32]) { ScalarMult(secret, priv, pub); }

    static VOID ScalarMult(UINT8 out[32], const UINT8 scalar_in[32], const UINT8 u_in[32]);
private:
    static const CFe25519 A24; 
    static const UINT8 BasePoint[32]; 
};

#endif // _X25519_H_


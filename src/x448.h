/* ========================================================================== */
/**
 * @file    x448.h
 * @brief   X448 key exchange class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_X448_H_)
#define _X448_H_

#include "fe448.h"

class CX448
{
public:
    static VOID PrivateKeyToPublicKey(UINT8 pub[56], const UINT8 priv[56]) { ScalarMult(pub, priv, BasePoint); }
    static VOID GetSharedSecret(UINT8 secret[56], const UINT8 priv[56], const UINT8 pub[56]) { ScalarMult(secret, priv, pub); }

    static VOID ScalarMult(UINT8 out[56], const UINT8 scalar_in[56], const UINT8 u_in[56]);
private:
    static const CFe448 A24; 
    static const UINT8 BasePoint[56]; 
};

#endif // _X448_H_


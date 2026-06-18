/* ========================================================================== */
/**
 * @file    ed25519.h
 * @brief   Ed25519 signature class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ED25519_H_)
#define _ED25519_H_

#include "BasicDefs.h"

VOID ed25519_keygen(const UINT8 seed[32], UINT8 pk[32], UINT8 hash[64]);
VOID ed25519_sign(const UINT8 seed[32], const UINT8 pk[32], const UINT8 * msg, UINT32 msg_len, UINT8 sig[64]);
BOOL ed25519_verify(const UINT8 pub[32], const UINT8 * msg, UINT32 msg_len, const UINT8 sig[64]);

#endif // _ED25519_H_


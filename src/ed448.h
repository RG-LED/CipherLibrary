/* ========================================================================== */
/**
 * @file    ed448.h
 * @brief   Ed448 signature class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ED448_H_)
#define _ED448_H_

#include "BasicDefs.h"

VOID ed448_keygen(const UINT8 seed[57], UINT8 pk_out[57]);
VOID ed448_sign(const UINT8 seed[57], const UINT8 pk[57], const CHAR8 * context, const UINT8 * m, SIZE_T mlen, UINT8 sig[114]);
INT32 ed448_verify(const UINT8 pk[57], const CHAR8 * context, const UINT8 * m, SIZE_T mlen, const UINT8 sig[114]);

#endif // _ED448_H_


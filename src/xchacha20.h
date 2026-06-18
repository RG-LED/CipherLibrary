/* ========================================================================== */
/**
 * @file    xchacha20.h
 * @brief   XChaCha20 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_XCHACHA20_H_)
#define _XCHACHA20_H_

#include "chacha20.h"

class CXChacha20 : public CChacha20
{
public:
#if SUPPORT_RESEED
    VOID Initialize(const UINT8 seed32[32], const UINT8 nonce24[24], UINT32 counter = 0, UINT64 reseed_interval_blocks = 0x9502f9129);
#else
    VOID Initialize(const UINT8 seed32[32], const UINT8 nonce24[24], UINT32 counter = 0);
#endif
};

#endif // #if !defined(_XCHACHA20_H_)


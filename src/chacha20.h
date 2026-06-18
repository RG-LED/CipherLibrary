/* ========================================================================== */
/**
 * @file    chacha20.h
 * @brief   ChaCha20 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_CHACHA20_H_)
#define _CHACHA20_H_

#include "BasicDefs.h"

#define SUPPORT_RESEED  1

class CChacha20
{
public:
    CChacha20();
#if SUPPORT_RESEED
    VOID Initialize(const UINT8 seed32[32], const UINT8 nonce12[12], UINT32 counter = 0, UINT64 reseed_interval_blocks = 0x9502f9129);
#else
    VOID Initialize(const UINT8 seed32[32], const UINT8 nonce12[12], UINT32 counter = 0);
#endif
    VOID Read(UINT8 * out, SIZE_T len);
    UINT8 Read8();
    UINT16 Read16();
    UINT32 Read32();
    VOID ReadXor(UINT8 * out, const UINT8 * in, SIZE_T len);
#if SUPPORT_RESEED
    BOOL NeedReseed() const;
    VOID Reseed(const UINT8 seed32[32], const UINT8 nonce12[12]);
#endif
    // UINT32 CChacha20::Take18();

protected:
    VOID Refill();
    static VOID RunChaChaRounds(UINT32 w[16]);

    /* --- little-endian helpers (portable) --- */
    static UINT32 Load32(const UINT8 * b)
        { return ((UINT32)b[0]) | ((UINT32)b[1] << 8) | ((UINT32)b[2] << 16) | ((UINT32)b[3] << 24); }
    static VOID Store32(UINT8 * b, UINT32 x)
        { b[0] = (UINT8)(x); b[1] = (UINT8)(x >> 8); b[2] = (UINT8)(x >> 16); b[3] = (UINT8)(x >> 24); }
    static UINT32 Rotl32(UINT32 x, INT32 r) { return (x << r) | (x >> (32 - r)); }

    UINT32 m_Key[8];     // 256-bit key
    UINT32 m_Nonce[3];   // 96-bit nonce
    UINT32 m_Counter;    // 32-bit block counter
    UINT8  m_Buf[64];    // buffered keystream (512-bit)
    SIZE_T  m_Avail;      // bytes remaining in buf
#if SUPPORT_RESEED
    UINT64 m_BlocksOut;  // number of 64B blocks produced (for reseed policy)
    UINT64 m_ReseedIntervalBlocks; // threshold to request reseed
#endif
};

#endif // #if !defined(_CHACHA20_H_)


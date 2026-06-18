/* ========================================================================== */
/**
 * @file    blake3.h
 * @brief   BLAKE3 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_BLAKE3_H_)
#define _BLAKE3_H_

#include "BasicDefs.h"

class CBlake3
{
public:
    CBlake3();
    ~CBlake3();

    VOID Initialize();
    VOID Update(const UINT8 * in, SIZE_T inlen);
    VOID Finish(UINT8 out[32]);
    VOID Finish();
    VOID GetOutput(UINT8 * out, SIZE_T len);

private:
    VOID Compress(UINT32 out[16], const UINT32 cv[8], const UINT8 block[64],
                  SIZE_T block_len, UINT64 counter, UINT32 flags);
    VOID ProcessChunk();
    VOID PushStack(const UINT32 * cv, UINT64 chunk_idx);
    static INT32 SearchBitPosition(UINT64 n, INT32 * msb);

    UINT64 m_counter;
    UINT8  m_buf[1024];
    SIZE_T m_bufLen;
    UINT32 m_stack[64][8]; // preserve Chaining Value (32 bytes) of each layer
    UINT32 m_rootCv[8];
    UINT8  m_rootSrc[64];
    UINT32 m_rootFlags;
    SIZE_T m_rootLen;
    UINT8  m_outBuf[64];
    SIZE_T m_outBufLen;
    static const UINT8 m_SIGMA[7][16];
    static const UINT32 IV[8];
};

#endif // !defined(_BLAKE3_H_)


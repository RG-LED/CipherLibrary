/* ========================================================================== */
/**
 * @file    poly1305.h
 * @brief   Poly1305 MAC class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_POLY1305_H_)
#define _POLY1305_H_

#include "FeBigInt256.h"

class CPoly1305
{
public:
    CPoly1305();
    ~CPoly1305();
    VOID Initialize(const UINT8 key[32]);
    VOID Update(const UINT8 * msg, SIZE_T len);
    VOID Finish(UINT8 tag[16]);
    VOID Reset();

private:
    VOID ProcessBlock();
    VOID MultiplyAndReduce();

    class CPolyKey : private CFeBigInt256 // do not use other methods of the base class
    {
    public:
        CPolyKey() { }
        CPolyKey(UINT32 n) : CFeBigInt256(n) { }
        VOID ClampR();
        VOID Reduce1305();
        static VOID Add(CPolyKey & out, const CPolyKey & n, const CPolyKey & m) { CFeBigInt256::Add(out, n, m); }
        static VOID Mul(CPolyKey & out, const CPolyKey & n, const CPolyKey & m);
        VOID fromBytesLE(const UINT8 * s, SIZE_T size) { CFeBigInt256::fromBytesLE(s, size); }
        VOID toBytesLE(UINT8 * out, SIZE_T size) const { CFeBigInt256::toBytesLE(out, size); }
    private:
        VOID ConditionalSubP();
    };

    CPolyKey m_r;   // clamped key (lower 130 bits are valid)
    CPolyKey m_h;   // accumulator
    CPolyKey m_s;   // final add key

    UINT8  m_buffer[16];    // 16B
    SIZE_T m_bufferLen;     // bytes in m_buffer
};

#endif // #if !defined(_POLY1305_H_)



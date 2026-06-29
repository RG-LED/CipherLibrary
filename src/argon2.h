/* ========================================================================== */
/**
 * @file    argon2.h
 * @brief   Argon2id password hashing class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ARGON2_H_)
#define _ARGON2_H_

#include "BasicDefs.h"

/************************************************************/
class CArgon2
{
public:
    CArgon2();
    ~CArgon2();

    BOOL Initialize(UINT8 mem[], SIZE_T memsize, INT32 pass, INT32 lane);

    VOID Hash(UINT8 tag[], UINT32 taglen,
              const UINT8 msg[], UINT32 msglen,
              const UINT8 nonce[], UINT32 noncelen,
              const UINT8 secret[], UINT32 secretlen,
              const UINT8 aad[], UINT32 aadlen);

private:
    static constexpr UINT32 SL = 4;
    static constexpr UINT32 BlockSize = 1024;

    UINT8 * Memory(INT32 lane, INT32 block)
        { return &m_mem[(lane * m_laneblocks + block) * BlockSize]; }
    VOID CalculateAddress(UINT8 * address,
                          INT32 p, INT32 l, INT32 s,
                          INT32 count, UINT8 * zero);
    VOID DecideIndex(INT32 & refl, INT32 & refz,
                     const UINT8 * address,
                     INT32 p, INT32 l, INT32 s, INT32 b);

    static VOID Hhash(UINT8 out[], UINT32 len, const UINT8 in[], UINT32 inlen);
    static VOID CompressionG(UINT8 out[1024],
                             const UINT8 in1[1024], const UINT8 in2[1024],
                             BOOL xorflag = FALSE);
    static VOID Permutation(UINT8 out[128], const UINT8 in[128]);

    UINT8 * m_mem;
    SIZE_T m_memsize;
    SIZE_T m_memblocks;
    INT32 m_segmentblocks;
    INT32 m_laneblocks;
    INT32 m_lanes;
    INT32 m_pass;
    INT32 m_type;
    INT32 m_version;
};

#endif // #if !defined(_ARGON2_H_)


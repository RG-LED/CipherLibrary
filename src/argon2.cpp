/* ========================================================================== */
/**
 * @file    argon2.cpp
 * @brief   Argon2id password hashing class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "argon2.h"
#include "blake2b.h"
#include "secure.h"

#include "stdio.h"

VOID datadump(const char c[], const VOID * dt, int len);

/************************************************************/
inline static VOID Store32LE(UINT8 b[4], UINT32 n)
{
    b[0] = (UINT8)n;
    b[1] = (UINT8)(n >> 8);
    b[2] = (UINT8)(n >> 16);
    b[3] = (UINT8)(n >> 24);
}

inline static VOID Store64LE(UINT8 b[8], UINT64 n)
{
    Store32LE(b, (UINT32)n);
    Store32LE(b + 4, (UINT32)(n >> 32));
}

inline static UINT32 Load32LE(const UINT8 b[4])
{
    return (UINT32)b[0] | ((UINT32)b[1] << 8) | ((UINT32)b[2] << 16) | ((UINT32)b[3] << 24);
}

inline static VOID Xor1024(UINT8 a[1024], const UINT8 b[1024])
{
    UINT64 * p = (UINT64 *)a;
    const UINT64 * q = (const UINT64 *)b;
    for ( INT32 i = 0; i < 1024 / 8; i++ )
    {
        p[i] ^= q[i];
    }
}

inline static VOID Xor1024(UINT8 a[1024], const UINT8 b[1024], const UINT8 c[1024])
{
    UINT64 * p = (UINT64 *)a;
    const UINT64 * q = (const UINT64 *)b;
    const UINT64 * r = (const UINT64 *)c;
    for ( INT32 i = 0; i < 1024 / 8; i++ )
    {
        p[i] = q[i] ^ r[i];
    }
}

inline static VOID Xor3_1024(UINT8 a[1024], const UINT8 b[1024], const UINT8 c[1024])
{
    UINT64 * p = (UINT64 *)a;
    const UINT64 * q = (const UINT64 *)b;
    const UINT64 * r = (const UINT64 *)c;
    for ( INT32 i = 0; i < 1024 / 8; i++ )
    {
        p[i] ^= q[i] ^ r[i];
    }
}

/************************************************************/
CArgon2::CArgon2()
{
    m_type = 2; // Argon2d = 0, Argon2i = 1, Argon2id = 2
    m_version = 0x13;
    m_mem = NULL;
    m_memblocks = 0;
}

CArgon2::~CArgon2()
{
    if ( m_mem != NULL )
    {
        secure_zero(m_mem, m_memblocks << 10);
    }
}

BOOL CArgon2::Initialize(UINT8 mem[], SIZE_T memsize, INT32 pass, INT32 lane)
{
    if ( lane < 1 || pass < 1 )
    {
        return FALSE;
    }

    m_segmentblocks = (UINT32)(memsize / (lane * BlockSize * SL));

    if ( m_segmentblocks < 2 )
    {
        return FALSE;
    }

    m_mem = mem;
    m_laneblocks = m_segmentblocks * SL;
    m_memsize = memsize >> 10;
    m_memblocks = m_laneblocks * lane;
    m_lanes = lane;
    m_pass = pass;

    return TRUE;
}

VOID CArgon2::Hash(UINT8 tag[], UINT32 taglen,
                   const UINT8 msg[], UINT32 msglen,
                   const UINT8 nonce[], UINT32 noncelen,
                   const UINT8 secret[], UINT32 secretlen,
                   const UINT8 aad[], UINT32 aadlen)
{
    UINT8 h0[64 + 8];
    UINT8 buf[4];
    CBlake2b blake;

    // Build H0
    blake.Initialize();
    Store32LE(buf, m_lanes);
    blake.Update(buf, sizeof(buf));
    Store32LE(buf, taglen);
    blake.Update(buf, sizeof(buf));
    Store32LE(buf, (UINT32)m_memsize);  // KB
    blake.Update(buf, sizeof(buf));
    Store32LE(buf, m_pass);
    blake.Update(buf, sizeof(buf));
    Store32LE(buf, m_version);
    blake.Update(buf, sizeof(buf));
    Store32LE(buf, m_type);
    blake.Update(buf, sizeof(buf));
    Store32LE(buf, msglen);
    blake.Update(buf, sizeof(buf));
    blake.Update(msg, msglen);
    Store32LE(buf, noncelen);
    blake.Update(buf, sizeof(buf));
    blake.Update(nonce, noncelen);
    Store32LE(buf, secretlen);
    blake.Update(buf, sizeof(buf));
    blake.Update(secret, secretlen);
    Store32LE(buf, aadlen);
    blake.Update(buf, sizeof(buf));
    blake.Update(aad, aadlen);
    blake.Finish(h0);

    // Build first two blocks in each lane
    for ( INT32 l = 0; l < m_lanes; l++ )
    {
        // B[l][0]
        Store32LE(h0 + 64, 0);
        Store32LE(h0 + 68, l);
        Hhash(Memory(l, 0), BlockSize, h0, sizeof(h0));

        // B[l][1]
        Store32LE(h0 + 64, 1);
        Hhash(Memory(l, 1), BlockSize, h0, sizeof(h0));
    }

    secure_zero(h0, sizeof(h0));

    UINT8 zero[1024];

    secure_zero(zero, sizeof(zero));

    // First pass
    for ( INT32 s = 0; s < SL; s++ )
    {
        for ( INT32 l = 0; l < m_lanes; l++ )
        {
            INT32 current = s * m_segmentblocks;
            INT32 count = 0;
            UINT8 address[1024];
            for ( INT32 b = 0; b < m_segmentblocks; b++, current++ )
            {
                if ( b % (1024 / 8) == 0 )
                {
                    CalculateAddress(address, 0, l, s, ++count, zero);
                }
                if ( current >= 2 )
                {
                    INT32 prev = (current + m_laneblocks - 1) % m_laneblocks;
                    INT32 refl, refz;
                    DecideIndex(refl, refz, address, 0, l, s, b);
                    CompressionG(Memory(l, current), Memory(l, prev), Memory(refl, refz));
                }
            }
        }
    }

    for ( INT32 p = 1; p < m_pass; p++ )
    {
        for ( INT32 s = 0; s < SL; s++ )
        {
            for ( INT32 l = 0; l < m_lanes; l++ )
            {
                INT32 current = s * m_segmentblocks;
                INT32 count = 0;
                UINT8 address[1024];
                for ( INT32 b = 0; b < m_segmentblocks; b++, current++ )
                {
                    INT32 prev = (current + m_laneblocks - 1) % m_laneblocks;
                    INT32 refl, refz;
                    if ( b % (1024 / 8) == 0 )
                    {
                        CalculateAddress(address, p, l, s, ++count, zero);
                    }
                    DecideIndex(refl, refz, address, p, l, s, b);
                    CompressionG(Memory(l, current), Memory(l, prev), Memory(refl, refz), TRUE);
                }
            }
        }
    }

    for ( INT32 l = 1; l < m_lanes; l++ )
    {
        Xor1024(Memory(0, m_laneblocks - 1), Memory(l, m_laneblocks - 1));
    }

    Hhash(tag, taglen, Memory(0, m_laneblocks - 1), BlockSize);
}

VOID CArgon2::CalculateAddress(UINT8 * address, INT32 p, INT32 l, INT32 s, INT32 count, UINT8 * zero)
{
    if ( p == 0 && s < 2 )
    {
        secure_zero(address, 1024);
        Store64LE(address, p);
        Store64LE(address + 8, l);
        Store64LE(address + 8 * 2, s);
        Store64LE(address + 8 * 3, m_memblocks);
        Store64LE(address + 8 * 4, m_pass);
        Store64LE(address + 8 * 5, m_type);
        Store64LE(address + 8 * 6, count);
        CompressionG(address, zero, address);
        CompressionG(address, zero, address);
    }
}

VOID CArgon2::DecideIndex(INT32 & refl, INT32 & refz,
                          const UINT8 * address, INT32 p, INT32 l, INT32 s, INT32 b)
{
    UINT32 j1, j2;

    if ( p == 0 && s < 2 )
    {
        INT32 pos = (b % (1024 / 8)) * 8;
        j1 = Load32LE(address + pos);
        j2 = Load32LE(address + pos + 4);

    }
    else
    {
        INT32 current = s * m_segmentblocks + b;
        INT32 prev = (current + m_laneblocks - 1) % m_laneblocks;
        j1 = Load32LE(Memory(l, prev));
        j2 = Load32LE(Memory(l, prev) + 4);
    }

    refl = (p == 0 && s == 0) ? l : (j2 % m_lanes);

    UINT32 top = 0;
    UINT32 area;
    if ( p == 0 )
    {
        if ( s == 0 )
        {
            area = b - 1; // never come here in case b < 1
        }
        else
        {
            area = s * m_segmentblocks;
            if ( refl == l )
            {
                area += b - 1;
            }
            else if ( b == 0 )
            {
                area--;
            }
        }
    }
    else
    {
        area = m_laneblocks - m_segmentblocks;
        if ( refl == l )
        {
            area += b - 1;
        }
        else if ( b == 0 )
        {
            area--;
        }
        if ( s < SL - 1 ) // not last slice
        {
            top = (s + 1) * m_segmentblocks; // next slice top
        }
    }
    UINT64 wk = ((UINT64)j1 * (UINT64)j1) >> 32;
    refz = (INT32)((top + area - 1 - (((UINT64)area * wk) >> 32)) % m_laneblocks);
}

VOID CArgon2::Hhash(UINT8 out[], UINT32 len, const UINT8 in[], UINT32 inlen)
{
    UINT8 v[64];

    CBlake2b blake;
    blake.Initialize(NULL, 0, (len < 64) ? len : 64);
    Store32LE(v, len);
    blake.Update(v, 4);
    blake.Update(in, inlen);
    blake.Finish(v);
    if ( len <= 64 )
    {
        memcpy(out, v, len);
    }
    else
    {
        UINT32 r = (len + 31) / 32 - 2;

        memcpy(out, v, 32);
        len -= 32;
        out += 32;

        for ( UINT32 i = 1; i < r; i++ )
        {
            blake.Initialize();
            blake.Update(v, sizeof(v));
            blake.Finish(v);
            memcpy(out, v, 32);
            len -= 32;
            out += 32;
        }
        if ( len > 0 )
        {
            blake.Initialize(NULL, 0, len);
            blake.Update(v, sizeof(v));
            blake.Finish(v);
            memcpy(out, v, len);
        }
    }
    secure_zero(v, sizeof(v));
}

VOID CArgon2::CompressionG(UINT8 out[1024], const UINT8 in1[1024], const UINT8 in2[1024], BOOL xorflag)
{
    UINT8 r[1024 + 1024];
    UINT8 q[1024 + 1024];
    UINT8 z[1024 + 1024];

    Xor1024(r, in1, in2);

    for ( INT32 i = 0; i < 8; i++ )
    {
        Permutation(q + i * 128, r + i * 128);
    }
    UINT8 b1[128];
    UINT8 b2[128];
    for ( INT32 i = 0; i < 8; i++ )
    {
        for ( INT32 j = 0; j < 8; j++ )
        {
            memcpy(b1 + j * 16, q + (j * 8 + i) * 16, 16);
        }
        Permutation(b2, b1);
        for ( INT32 j = 0; j < 8; j++ )
        {
            memcpy(z + (j * 8 + i) * 16, b2 + j * 16, 16);
        }
    }
    if ( xorflag )
    {
        Xor3_1024(out, z, r);
    }
    else
    {
        Xor1024(out, z, r);
    }
    secure_zero(r, sizeof(r));
    secure_zero(q, sizeof(q));
    secure_zero(z, sizeof(z));
    secure_zero(b1, sizeof(b1));
    secure_zero(b2, sizeof(b2));
}

#define ROTR64(x, n)    (((x) >> (n)) | ((x) << (64u - (n))))
#define TRUNC32(x)      ((x) & 0x00000000ffffffffllu)
#define GB(a, b, c, d) { \
    (a) = (a) + (b) + 2 * TRUNC32(a) * TRUNC32(b); (d) = ROTR64((d) ^ (a), 32); \
    (c) = (c) + (d) + 2 * TRUNC32(c) * TRUNC32(d); (b) = ROTR64((b) ^ (c), 24); \
    (a) = (a) + (b) + 2 * TRUNC32(a) * TRUNC32(b); (d) = ROTR64((d) ^ (a), 16); \
    (c) = (c) + (d) + 2 * TRUNC32(c) * TRUNC32(d); (b) = ROTR64((b) ^ (c), 63); }

VOID CArgon2::Permutation(UINT8 out[128], const UINT8 in[128])
{
    UINT64 * v = (UINT64 *)out;
    memcpy(out, in, 128);
    GB(v[0], v[4], v[ 8], v[12])
    GB(v[1], v[5], v[ 9], v[13])
    GB(v[2], v[6], v[10], v[14])
    GB(v[3], v[7], v[11], v[15])
    GB(v[0], v[5], v[10], v[15])
    GB(v[1], v[6], v[11], v[12])
    GB(v[2], v[7], v[ 8], v[13])
    GB(v[3], v[4], v[ 9], v[14])
}


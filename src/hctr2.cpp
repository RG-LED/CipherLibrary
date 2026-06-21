/* ========================================================================== */
/**
 * @file    hctr2.cpp
 * @brief   HCTR2 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "hctr2.h"


/************************************************************/

VOID CPolyvalEx::Init(const CGf128LE & h)
{
    CPolyval::Init(h);
    m_buflen = 0;
}


VOID CPolyvalEx::Update(const UINT8 * in, SIZE_T len)
{
    while ( len > 0 )
    {
        SIZE_T take = sizeof(m_buf) - m_buflen;
        if ( take > len )
        {
            take = len;
        }
        memcpy(m_buf + m_buflen, in, take);
        m_buflen += take;
        in += take;
        len -= take;
        if ( m_buflen >= 16 )
        {
            UpdateBlock(m_buf);
            m_buflen = 0;
        }
    }
}


VOID CPolyvalEx::Flush()
{
    if ( m_buflen > 0 )
    {
        secure_zero(m_buf + m_buflen, sizeof(m_buf) - m_buflen);
        UpdateBlock(m_buf);
        m_buflen = 0;
    }
}


VOID CPolyvalEx::Final(UINT64 aad_bits, UINT64 c_bits)
{
    Flush();
    CPolyval::Final(aad_bits, c_bits);
}

/************************************************************/

template<>
VOID CHctr2<Hctr2Spec::POLYVAL>::MakeTweak(UINT8 tweak[16],
                                           const UINT8 * nonce, SIZE_T noncelen,
                                           const UINT8 * aad, SIZE_T aadlen)
{
    CPolyvalEx hash;
    CGf128LE h;
    h.LoadLE(m_h);

    hash.Init(h);
    UINT8 c = 0x01; // domain separater
    hash.Update(&c, 1);
    hash.Update(nonce, noncelen);
    hash.Flush();

    c = 0x02;   // domain separater
    hash.Update(&c, 1);
    hash.Update(aad, aadlen);
    hash.Flush();

    hash.Final(noncelen, aadlen);
    hash.Get(tweak);
}


template<>
VOID CHctr2<Hctr2Spec::POLYVAL>::Hash(UINT8 out[16],
                                      const UINT8 * n, SIZE_T nlen,
                                      const UINT8 * tweak, SIZE_T twlen)
{
    SIZE_T len = twlen * 8 * 2 + 2;
    UINT8 block[16];
    BOOL awkward = ((nlen % 16) != 0);
    if ( awkward )
    {
        len++;
    }
    for ( INT32 i = 0; i < sizeof(block); i++ )
    {
        block[i] = (UINT8)len;
        len >>= 8;
    }

    CPolyvalEx hash;
    CGf128LE h;
    h.LoadLE(m_h);

    hash.Init(h);
    hash.Update(block, sizeof(block));
    hash.Update(tweak, twlen);
    hash.Flush();
    hash.Update(n, nlen);
    if ( awkward )
    {
        UINT8 c = 0x01;
        hash.Update(&c, 1);
    }
    hash.Flush();
    hash.Get(out);
    secure_zero(block, sizeof(block));
}

/************************************************************/

template<>
VOID CHctr2<Hctr2Spec::AESCMAC>::MakeTweak(UINT8 tweak[16],
                                           const UINT8 * nonce, SIZE_T noncelen,
                                           const UINT8 * aad, SIZE_T aadlen)
{
    UINT8 wk[16] = { 0 };
    CAesCmac hash;

    hash.SetKeys(m_h, sizeof(m_h));

    UINT8 c = 0x01; // domain separater
    hash.Update(&c, 1);
    hash.Update(nonce, noncelen);
    hash.Update(wk, 15 - (noncelen % 16));

    c = 0x02;   // domain separater
    hash.Update(&c, 1);
    hash.Update(aad, aadlen);
    hash.Update(wk, 15 - (aadlen % 16));

    SIZE_T noncebit = noncelen * 8;
    SIZE_T aadbit = aadlen * 8;
    for ( INT32 i = 0; i < 8; i++ )
    {
        wk[i    ] = (UINT8)(noncebit >> (i * 8));
        wk[i + 8] = (UINT8)(aadbit   >> (i * 8));
    }
    hash.Update(wk, sizeof(wk));

    hash.Finish(tweak);
    secure_zero(wk, sizeof(wk));
}


template<>
VOID CHctr2<Hctr2Spec::AESCMAC>::Hash(UINT8 out[16],
                                      const UINT8 * n, SIZE_T nlen,
                                      const UINT8 * tweak, SIZE_T twlen)
{
    SIZE_T len = twlen * 8 * 2 + 2;
    UINT8 block[16];
    BOOL awkward = ((nlen % 16) != 0);
    if ( awkward )
    {
        len++;
    }
    for ( INT32 i = 0; i < sizeof(block); i++ )
    {
        block[i] = (UINT8)len;
        len >>= 8;
    }

    static const UINT8 zero[16] = { 0 };
    CAesCmac hash;

    hash.SetKeys(m_h, sizeof(m_h));
    hash.Update(block, sizeof(block));

    hash.Update(tweak, twlen);
    hash.Update(zero, 15 - ((twlen + 15) % 16));

    hash.Update(n, nlen);
    if ( awkward )
    {
        UINT8 c = 0x01;
        hash.Update(&c, 1);
        nlen++;
    }
    hash.Update(zero, 15 - ((nlen + 15) % 16));

    hash.Finish(out);
    secure_zero(block, sizeof(block));
}

/************************************************************/


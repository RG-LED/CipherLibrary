/* ========================================================================== */
/**
 * @file    aesccm.cpp
 * @brief   AES-CCM cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "aesccm.h"
#include "secure.h"

/************************************************************/
CAesCcm::CAesCcm()
{
    Initialize();
    m_M = 16;
    m_L = 3;
    m_keyLen = 16;
}

CAesCcm::~CAesCcm()
{
    Initialize();
}

VOID CAesCcm::Initialize()
{
    secure_zero(m_block, sizeof(m_block));
}

BOOL CAesCcm::Encrypt(UINT8 * cipher, const UINT8 * msg, SIZE_T mlen,
                      const UINT8 * nonce, SIZE_T nlen,
                      const UINT8 * aad, SIZE_T alen,
                      const UINT8 * key, SIZE_T klen, SIZE_T tlen)
{
    if ( !SetParameter(mlen, nlen, klen, tlen) ||
         !SetKeys(key, m_keyLen) )
    {
        return FALSE;
    }

    FirstBlock(nonce, alen, mlen);
    FeedAad(aad, alen);
    FeedMessage(msg, mlen);

    BuildCounterBlock(nonce);
    UINT8 tag[16];
    MakeTag(tag);

    // encrypt 'msg' and write into buffer 'cipher'
    ConvertMessage(cipher, msg, mlen);

    // append 'tag' of m_M bytes after cipher text
    memcpy(&cipher[mlen], tag, m_M);

    return TRUE;
}

BOOL CAesCcm::Decrypt(UINT8 * msg, const UINT8 * cipher, SIZE_T clen,
                      const UINT8 * nonce, SIZE_T nlen,
                      const UINT8 * aad, SIZE_T alen,
                      const UINT8 * key, SIZE_T klen, SIZE_T tlen)
{
    if ( clen < tlen )
    {
        return FALSE;
    }
    SIZE_T mlen = clen - tlen; // plaintext length = ciphertext length - tag length
    if ( clen < tlen ||
         !SetParameter(mlen, nlen, klen, tlen) ||
         !SetKeys(key, m_keyLen) )
    {
        return FALSE;
    }

    BuildCounterBlock(nonce);

    // decrypt 'cipher' and write into buffer 'msg'
    ConvertMessage(msg, cipher, mlen);

    FirstBlock(nonce, alen, mlen);
    FeedAad(aad, alen);
    FeedMessage(msg, mlen);

    BuildCounterBlock(nonce);
    UINT8 tag[16];
    MakeTag(tag);

    if ( !secure_equal(&cipher[mlen], tag, m_M) )
    {
        secure_zero(msg, mlen);
        return FALSE;
    }

    return TRUE;
}

BOOL CAesCcm::SetParameter(SIZE_T mlen, SIZE_T nlen, SIZE_T klen, SIZE_T tlen)
{
    // tag length (M) must be 4, 6, 8, 10, 12, 14 or 16
    if ( tlen < 4 || tlen > 16 || (tlen % 2) != 0 )
    {
        return FALSE;
    }

    // nonce length must be within 7 to 13 bytes
    if ( nlen < 7 || nlen > 13 )
    {
        return FALSE;
    }

    // length indicator (L)
    // nonce length + L = 15
    SIZE_T L = 15 - nlen;

    // if plaintext length (mlen) fits in L bytes
    if ( L < 8 )
    {
        if ( mlen > (1ull << (8 * L)) - 1 )
        {
            return FALSE; // too large data for this nonce length (L)
        }
    }

    // check key length is 16, 24 or 32
    if ( klen != 16 && klen != 24 && klen != 32 )
    {
        return FALSE;
    }

    m_L = L;
    m_M = tlen;
    m_keyLen = klen;

    return TRUE;
}

VOID CAesCcm::FirstBlock(const UINT8 * nonce, SIZE_T alen, SIZE_T mlen)
{
    Initialize();
    m_block[0] = (UINT8)(((alen > 0) ? 0x40 : 0) | (((m_M - 2) / 2) << 3) | (m_L - 1));
    memcpy(&m_block[1], nonce, 15 - m_L);
    for ( SIZE_T i = 0; i < m_L; i++ )
    {
        m_block[15 - i] = (UINT8)mlen;
        mlen >>= 8;
    }
    EncryptBlock(m_block);
}


VOID CAesCcm::FeedAad(const UINT8 * aad, SIZE_T alen)
{
    if ( alen > 0 )
    {
        UINT8 buf[16];
        SIZE_T room;

        if ( alen < 0xff00ull )
        {
            buf[0] = (UINT8)(alen >> 8);
            buf[1] = (UINT8)alen;
            room = sizeof(buf) - 2;
        }
        else if ( alen <= 0xffffffffull )
        {
            buf[0] = 0xff;
            buf[1] = 0xfe;
            buf[2] = (UINT8)(alen >> 24);
            buf[3] = (UINT8)(alen >> 16);
            buf[4] = (UINT8)(alen >> 8);
            buf[5] = (UINT8)alen;
            room = sizeof(buf) - 6;
        }
        else
        {
            buf[0] = 0xff;
            buf[1] = 0xff;
            buf[2] = (UINT8)((UINT64)alen >> 56);
            buf[3] = (UINT8)((UINT64)alen >> 48);
            buf[4] = (UINT8)((UINT64)alen >> 40);
            buf[5] = (UINT8)((UINT64)alen >> 32);
            buf[6] = (UINT8)(alen >> 24);
            buf[7] = (UINT8)(alen >> 16);
            buf[8] = (UINT8)(alen >> 8);
            buf[9] = (UINT8)alen;
            room = sizeof(buf) - 10;
        }

        while ( alen >= room )
        {
            memcpy(&buf[sizeof(buf) - room], aad, room);
            FeedBlock(buf);

            alen -= room;
            aad += room;
            room = sizeof(buf);
        }
        if ( alen > 0 )
        {
            memcpy(&buf[sizeof(buf) - room], aad, alen);
            room -= alen;
            secure_zero(&buf[sizeof(buf) - room], room);
            FeedBlock(buf);
        }
    }
}

VOID CAesCcm::FeedMessage(const UINT8 * msg, SIZE_T mlen)
{
    while ( mlen >= 16 )
    {
        FeedBlock(msg);
        msg += 16;
        mlen -= 16;
    }
    if ( mlen > 0 )
    {
        UINT8 buf[16];
        secure_zero(buf, sizeof(buf));
        memcpy(buf, msg, mlen);
        FeedBlock(buf);
    }
}

VOID CAesCcm::FeedBlock(const UINT8 block[16])
{
    for ( SIZE_T i = 0; i < sizeof(m_block); i++ )
    {
        m_block[i] ^= block[i];
    }
    EncryptBlock(m_block);
}

VOID CAesCcm::BuildCounterBlock(const UINT8 * nonce)
{
    // build first counter block (A0)
    secure_zero(m_counter, sizeof(m_counter));
    m_counter[0] = (UINT8)(m_L - 1);       // Flags: L-1
    memcpy(&m_counter[1], nonce, 15 - m_L);   // copy nonce
}

VOID CAesCcm::MakeTag(UINT8 tag[16])
{
    // encrypt authentication tag (use reserved counter 0)
    UINT8 s0[16];
    memcpy(s0, m_counter, sizeof(s0));
    EncryptBlock(s0); // encrypt a0
    for ( SIZE_T i = 0; i < m_M; i++ )
    {
        tag[i] = m_block[i] ^ s0[i]; // XOR raw tag (m_block) with encrypted a0
    }
}

VOID CAesCcm::IncrementCounter()
{
    for ( SIZE_T i = 0; i < m_L; i++ )
    {
        if ( ++m_counter[sizeof(m_counter) - i - 1] > 0 )
        {
            break;
        }
    }
}

VOID CAesCcm::ConvertMessage(UINT8 * out, const UINT8 * msg, SIZE_T mlen)
{
    while ( mlen >= 16 )
    {
        ConvertBlock(out, msg, 16);
        msg += 16;
        out += 16;
        mlen -= 16;
    }
    if ( mlen > 0 )
    {
        UINT8 buf[16];
        secure_zero(buf, sizeof(buf));
        memcpy(buf, msg, mlen);
        ConvertBlock(out, buf, mlen);
    }
}

VOID CAesCcm::ConvertBlock(UINT8 * out, const UINT8 * msg, SIZE_T mlen)
{
    IncrementCounter();
    UINT8 enc[16];
    memcpy(enc, m_counter, sizeof(enc));
    EncryptBlock(enc);
    for ( SIZE_T i = 0; i < mlen; i++ )
    {
        out[i] = msg[i] ^ enc[i];
    }
}


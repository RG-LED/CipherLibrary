/* ========================================================================== */
/**
 * @file    aesctr_drbg.cpp
 * @brief   AES-CTR random generator class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "aesctr_drbg.h"

#define MAX_SEEDLEN     48
#define RESEED_INTERVAL (1ull << 48)    // 2^48

class CAesCtrDrbg::CDerivation : protected CAesBase
{
public:
    CDerivation(UINT32 outputSize);
    VOID Calc(const UINT8 * data1, SIZE_T len1, const UINT8 * data2, SIZE_T len2, const UINT8 * data3, SIZE_T len3);
    VOID GetResult(UINT8 * out);
private:
    VOID ProcessData(const UINT8 * data, SIZE_T len);
    UINT32 m_outputSize;
    UINT32 m_keySize;
    UINT8 m_output[MAX_SEEDLEN];
    UINT8 m_buf[NBb];
    UINT8 m_chain[NBb];
    SIZE_T m_buflen;
};

CAesCtrDrbg::CDerivation::CDerivation(UINT32 outputSize)
{
    m_outputSize = outputSize;
    m_keySize = outputSize - NBb;
}

VOID CAesCtrDrbg::CDerivation::Calc(const UINT8 * data1, SIZE_T len1,
                                    const UINT8 * data2, SIZE_T len2,
                                    const UINT8 * data3, SIZE_T len3)
{
    UINT32 len = (UINT32)(len1 + len2 + len3);
    UINT8 header[8];

    for ( INT32 i = 0; i < 4; i++ )
    {
        header[i] = (UINT8)(len >> (24 - i * 8));
        header[i + 4] = (UINT8)(m_outputSize >> (24 - i * 8));
    }

    static const UINT8 key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    UINT8 iv[NBb];
    UINT8 output[MAX_SEEDLEN];

    secure_zero(iv, sizeof(iv));
    SetKeys(key, m_keySize);

    for ( UINT32 i = 0; i < (m_outputSize + NBb - 1) / NBb; i++ )
    {
        secure_zero(m_chain, sizeof(m_chain));
        m_buflen = 0;

        iv[3] = (UINT8)i; // 2 at most
        ProcessData(iv, sizeof(iv));
        ProcessData(header, sizeof(header));
        ProcessData(data1, len1);
        ProcessData(data2, len2);
        ProcessData(data3, len3);

        m_buf[m_buflen++] = 0x80;
        secure_zero(m_buf + m_buflen, sizeof(m_buf) - m_buflen);

        for ( INT32 j = 0; j < NBb; j++ )
        {
            m_chain[j] ^= m_buf[j];
        }
        EncryptBlock(m_chain);
        memcpy(output + i * NBb, m_chain, NBb);
    }

    SetKeys(output, m_keySize);
    memcpy(m_buf, output + m_keySize, NBb);
    for ( UINT32 i = 0; i < m_outputSize; i += NBb )
    {
        EncryptBlock(m_buf);
        memcpy(m_output + i, m_buf, NBb);
    }

    secure_zero(header, sizeof(header));
    secure_zero(iv, sizeof(iv));
    secure_zero(output, sizeof(output));
}

VOID CAesCtrDrbg::CDerivation::ProcessData(const UINT8 * data, SIZE_T len)
{
    SIZE_T pos = 0;

    while ( pos < len )
    {
        SIZE_T take = sizeof(m_buf) - m_buflen;
        if ( take > (len - pos) )
        {
            take = len - pos;
        }
        memcpy(m_buf + m_buflen, data + pos, take);
        m_buflen += take;
        pos += take;
        if ( m_buflen >= sizeof(m_buf) )
        {
            for ( INT32 i = 0; i < NBb; i++ )
            {
                m_chain[i] ^= m_buf[i];
            }
            EncryptBlock(m_chain);
            m_buflen = 0;
        }
    }
}

VOID CAesCtrDrbg::CDerivation::GetResult(UINT8 * out)
{
    memcpy(out, m_output, m_outputSize);
}

/*****************************************************/

BOOL CAesCtrDrbg::Setup(INT32 keyLen, BOOL useDf)
{
    secure_zero(m_key, sizeof(m_key));
    BOOL ret = SetKeys(m_key, keyLen);
    if ( ret )
    {
        secure_zero(m_vector, sizeof(m_vector));
        m_keyLen = keyLen;
        m_seedLen = keyLen + NBb;
        m_useDf = useDf;
    }
    return ret;
}

BOOL CAesCtrDrbg::Instantiate(const UINT8 * entropy, SIZE_T eLen,
                              const UINT8 * nonce, SIZE_T nLen,
                              const UINT8 * personal, SIZE_T pLen)
{
    UINT8 seed[MAX_SEEDLEN];

    if ( m_useDf )
    {
        CDerivation df(m_seedLen);
        df.Calc(entropy, eLen, nonce, nLen, personal, pLen);
        df.GetResult(seed);
    }
    else
    {
        if ( eLen != m_seedLen || pLen > m_seedLen )
        {
            return FALSE;
        }

        secure_zero(seed, sizeof(seed));
        memcpy(seed, personal, pLen);
        for ( UINT32 i = 0; i < m_seedLen; i++ )
        {
            seed[i] ^= entropy[i];
        }
    }

    Update(seed);
    m_reseedCounter = 1;

    secure_zero(seed, sizeof(seed));

    return TRUE;
}


BOOL CAesCtrDrbg::Reseed(const UINT8 * entropy, SIZE_T eLen,
                         const UINT8 * additional, SIZE_T aLen)
{
    UINT8 seed[MAX_SEEDLEN];

    if ( m_useDf )
    {
        CDerivation df(m_seedLen);
        df.Calc(entropy, eLen, additional, aLen, NULL, 0);
        df.GetResult(seed);
    }
    else
    {
        if ( eLen != m_seedLen || aLen > m_seedLen )
        {
            return FALSE;
        }

        secure_zero(seed, sizeof(seed));
        memcpy(seed, additional, aLen);
        for ( UINT32 i = 0; i < m_seedLen; i++ )
        {
            seed[i] ^= entropy[i];
        }
    }

    Update(seed);
    m_reseedCounter = 1;

    secure_zero(seed, sizeof(seed));

    return TRUE;
}

BOOL CAesCtrDrbg::Generate(UINT8 * out, SIZE_T oLen,
                           const UINT8 * additional, SIZE_T aLen)
{
    if ( m_reseedCounter > RESEED_INTERVAL )
    {
        return FALSE;
    }

    UINT8 add[MAX_SEEDLEN];
    if ( additional != NULL && aLen > 0 )
    {
        if ( m_useDf )
        {
            CDerivation df(m_seedLen);
            df.Calc(additional, aLen, NULL, 0, NULL, 0);
            df.GetResult(add);
        }
        else
        {
            secure_zero(add, m_seedLen);
            memcpy(add, additional, (aLen > m_seedLen) ? m_seedLen : aLen);
        }
        Update(add);
    }
    else
    {
        secure_zero(add, sizeof(add));
    }

    UINT8 buf[NBb];
    while ( oLen > 0 )
    {
        IncrementVector();
        memcpy(buf, m_vector, sizeof(buf));
        EncryptBlock(buf);
        SIZE_T take = (oLen > NBb) ? NBb : oLen;
        memcpy(out, buf, take);
        out += take;
        oLen -= take;
    }

    Update(add);
    m_reseedCounter++;

    secure_zero(add, sizeof(add));
    secure_zero(buf, sizeof(buf));

    return TRUE;
}

VOID CAesCtrDrbg::Update(const UINT8 * data)
{
    UINT8 buf[MAX_SEEDLEN];

    UINT32 ceiling = ((m_seedLen + NBb - 1) / NBb) * NBb;
    for ( UINT32 i = 0; i < ceiling; i += NBb )
    {
        IncrementVector();
        memcpy(&buf[i], m_vector, sizeof(m_vector));
        EncryptBlock(&buf[i]);
    }
    for ( UINT32 i = 0; i < m_seedLen; i++ )
    {
        buf[i] ^= data[i];
    }
    memcpy(m_key, buf, m_keyLen);
    SetKeys(m_key, m_keyLen);
    memcpy(m_vector, &buf[m_keyLen], sizeof(m_vector));

    secure_zero(buf, sizeof(buf));
}


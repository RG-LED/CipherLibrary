/* ========================================================================== */
/**
 * @file    aesKeyWrap.cpp
 * @brief   AES Key Wrap class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "aesKeyWrap.h"
#include "secure.h"


static const UINT8 defaultIV[8] = {
    0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6
};
static const UINT8 defaultIVp[4] = {
    0xa6, 0x59, 0x59, 0xa6
};


CAesKeyWrap::CAesKeyWrap()
{
    secure_zero(m_a, sizeof(m_a));
    m_kwp = FALSE;
}

CAesKeyWrap::~CAesKeyWrap()
{
    secure_zero(m_a, sizeof(m_a));
}


BOOL CAesKeyWrap::SetKeys(const UINT8 keys[], SIZE_T len)
{
    BOOL ret = CAesBase::SetKeys(keys, len);
    if ( ret )
    {
        m_kwp = FALSE;
        memcpy(m_a, defaultIV, sizeof(m_a));
    }
    return ret;
}


VOID CAesKeyWrap::SwitchToKwp()
{
    m_kwp = TRUE;
    memcpy(m_a, defaultIVp, sizeof(defaultIVp));
}


BOOL CAesKeyWrap::KeyWrap(UINT8 * data, SIZE_T & len, UINT8 tag[8])
{
    SIZE_T blocks = (len + 7) / 8;
    SIZE_T rem = len & 7;

    if ( m_kwp )
    {
        if ( blocks < 1 )
        {
            return FALSE;
        }
        m_a[4] = (UINT8)(len >> 24);
        m_a[5] = (UINT8)(len >> 16);
        m_a[6] = (UINT8)(len >> 8);
        m_a[7] = (UINT8)len;
        if ( rem > 0 )
        {
            secure_zero(data + len, 8 - rem);
        }
        if ( blocks == 1 )
        {
            UINT8 buf[16];
            memcpy(buf, m_a, 8);
            memcpy(buf + 8, data, 8);

            EncryptBlock(buf);

            memcpy(tag, buf, 8);
            memcpy(data, buf + 8, 8);
            len = blocks * 8;
            return TRUE;
        }
    }
    else if ( blocks < 2 || rem != 0 )
    {
        return FALSE;
    }

    for ( INT32 j = 0; j < 6; j++ )
    {
        for ( INT32 i = 0; i < (INT32)blocks; i++ )
        {
            UINT8 buf[16];
            memcpy(buf, m_a, 8);
            memcpy(buf + 8, &data[i * 8], 8);

            EncryptBlock(buf);

            memcpy(m_a, buf, 8);
            SIZE_T t = (blocks * j) + i + 1;
            for ( INT32 k = 7; k >= 0; k-- )
            {
                m_a[k] ^= (UINT8)t;
                t >>= 8;
            }
            memcpy(&data[i * 8], buf + 8, 8);
        }
    }

    memcpy(tag, m_a, 8);
    len = blocks * 8;

    return TRUE;
}


BOOL CAesKeyWrap::KeyUnwrap(UINT8 * data, SIZE_T & len, const UINT8 tag[8])
{
    if ( len < (m_kwp ? 8u : 16u) || (len & 7) != 0 )
    {
        return FALSE;
    }

    SIZE_T blocks = len / 8;

    if ( blocks == 1 )
    {
        UINT8 buf[16];
        memcpy(buf, tag, 8);
        memcpy(buf + 8, data, 8);

        DecryptBlock(buf);

        memcpy(m_a, buf, 8);
        memcpy(data, buf + 8, 8);
    }
    else
    {
        memcpy(m_a, tag, sizeof(m_a));

        for ( INT32 j = 5; j >= 0; j-- )
        {
            for ( INT32 i = (INT32)(blocks - 1); i >= 0; i-- )
            {
                SIZE_T t = (blocks * j) + i + 1;
                for ( INT32 k = 7; k >= 0; k-- )
                {
                    m_a[k] ^= (UINT8)t;
                    t >>= 8;
                }

                UINT8 buf[16];

                memcpy(buf, m_a, 8);
                memcpy(buf + 8, &data[i * 8], 8);

                DecryptBlock(buf);

                memcpy(m_a, buf, 8);
                memcpy(&data[i * 8], buf + 8, 8);
            }
        }
    }

    if ( m_kwp )
    {
        if ( !secure_equal(m_a, defaultIVp, sizeof(defaultIVp)) )
        {
            secure_zero(data, len);
            return FALSE;
        }

        UINT32 size = m_a[7] | ((UINT32)m_a[6] << 8) | ((UINT32)m_a[5] << 16) | ((UINT32)m_a[4] << 24);
        SIZE_T rem = len - size;
        static const UINT8 zero[8] = { 0 };

        if ( size <= (blocks - 1) * 8 || blocks * 8 < size || !secure_equal(&data[size], zero, rem) )
        {
            secure_zero(data, len);
            return FALSE;
        }
        len = size;
    }
    else
    {
        if ( !secure_equal(m_a, defaultIV, sizeof(m_a)) )
        {
            secure_zero(data, len);
            return FALSE;
        }
    }

    return TRUE;
}


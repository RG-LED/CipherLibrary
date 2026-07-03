/* ========================================================================== */
/**
 * @file    ascon128a.cpp
 * @brief   Ascon-128a cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "ascon128a.h"
#include "secure.h"

VOID CAscon128a::Initialize(const UINT8 key[16], const UINT8 nonce[16], const UINT8 * ad, SIZE_T adlen)
{
    // algorithm parameter (Key-length=128, Rate=128, a=12, b=8)
    CAsconAead::Initialize(key, nonce, 0x80800c0800000000ull);

    // process Associated Data
    if ( adlen > 0 )
    {
        // 1. 16-byte (128 bits) block process
        while ( adlen >= 16 )
        {
            // XOR m_state with converted 128-bit data
            m_state[0] ^= BytesToUint64(ad);
            m_state[1] ^= BytesToUint64(ad + 8);

            // scramble 8 rounds
            Permutation(8);

            ad += 16;
            adlen -= 16;
        }

        // 2. padding
        SIZE_T first;
        SIZE_T second;
        if ( adlen >= 8 )
        {
            first = 8;
            second = adlen - 8;
        }
        else
        {
            first = adlen;
            second = 0;
        }
        UINT64 last_block1 = BytesToUint64(ad, first);
        UINT64 last_block2 = BytesToUint64(ad + 8, second);

        // set bit at the next position
        if ( first < 8 )
        {
            last_block1 |= (0x80ull << (56 - (first * 8)));
        }
        else
        {
            last_block2 |= (0x80ull << (56 - (second * 8)));
        }

        m_state[0] ^= last_block1;
        m_state[1] ^= last_block2;
        Permutation(8);
    }
    // 3. domain separation
    // XOR LSB of state tail with 1
    m_state[4] ^= 1ull;
}


VOID CAscon128a::Encrypt(UINT8 * out, UINT8 tag[16], const UINT8 * message, SIZE_T msglen)
{
    // 1. 16-byte (128 bits) block process
    while ( msglen >= 16 )
    {
        // XOR 0th and 1st of m_state with plaintext
        m_state[0] ^= BytesToUint64(message);
        m_state[1] ^= BytesToUint64(message + 8);

        // extract ciphertext from 0th and 1st of m_state
        Uint64ToBytes(out, m_state[0]);
        Uint64ToBytes(out + 8, m_state[1]);

        // replace 8 rounds
        Permutation(8);

        message += 16;
        out += 16;
        msglen -= 16;
    }

    // 2. padding
    SIZE_T first;
    SIZE_T second;
    if ( msglen >= 8 )
    {
        first = 8;
        second = msglen - 8;
    }
    else
    {
        first = msglen;
        second = 0;
    }
    UINT64 last_block1 = BytesToUint64(message, first);
    UINT64 last_block2 = BytesToUint64(message + 8, second);

    // set 1 bit at tail of data
    if ( first < 8 )
    {
        last_block1 |= ((UINT64)0x80 << (56 - (first * 8)));
    }
    else
    {
        last_block2 |= ((UINT64)0x80 << (56 - (second * 8)));
    }

    // XOR 0th and 1st m_state with padding
    m_state[0] ^= last_block1;
    m_state[1] ^= last_block2;

    // extract last fragment of cipertext from 0th and 1st of m_state
    Uint64ToBytes(out, m_state[0], first);
    Uint64ToBytes(out + 8, m_state[1], second);

    Finish(tag);
}


BOOL CAscon128a::Decrypt(UINT8 * out, const UINT8 * cipher, SIZE_T cphlen, const UINT8 tag[16])
{
    SIZE_T len = cphlen;
    UINT8 * ptr = out;

    // 1. 16-byte (128 bits) block process
    while ( len >= 16 )
    {
        // convert current chipertext block to two 64-bit data
        UINT64 c_block1 = BytesToUint64(cipher);
        UINT64 c_block2 = BytesToUint64(cipher + 8);

        // plaintext = m_state[0/1] ^ ciphertext
        UINT64 block1 = m_state[0] ^ c_block1;
        UINT64 block2 = m_state[1] ^ c_block2;

        // store plaintext
        Uint64ToBytes(ptr, block1);
        Uint64ToBytes(ptr + 8, block2);

        // overwrite state with ciphertext
        m_state[0] = c_block1;
        m_state[1] = c_block2;

        // replace 8 rounds (preparing next block)
        Permutation(8);

        cipher += 16;
        ptr += 16;
        len -= 16;
    }

    // 2. padding
    SIZE_T first;
    SIZE_T second;
    if ( len >= 8 )
    {
        first = 8;
        second = len - 8;
    }
    else
    {
        first = len;
        second = 0;
    }
    UINT64 c_last1 = BytesToUint64(cipher, first);
    UINT64 c_last2 = BytesToUint64(cipher + 8, second);

    // decrypt fragment block: plaintext = state ^ ciphertext
    UINT64 last1 = m_state[0] ^ c_last1;
    UINT64 last2 = m_state[1] ^ c_last2;

    // store last fragment
    Uint64ToBytes(ptr, last1, first);
    Uint64ToBytes(ptr + 8, last2, second);

    // update state
    UINT64 mask = 0xffffffffffffffffllu;
    mask >>= (first * 4);   // result of shifting 64bits once may depend on environment
    mask >>= (first * 4);
    m_state[0] &= mask;     // clear processed bits
    m_state[0] |= c_last1;  // embed ciphertext
    mask = 0xffffffffffffffffllu;
    mask >>= (second * 4);  // result of shifting 64bits once may depend on environment
    mask >>= (second * 4);
    m_state[1] &= mask;     // clear processed bits
    m_state[1] |= c_last2;  // embed ciphertext
    if ( first < 8 )
    {
        m_state[0] ^= (0x80ull << (56 - (first * 8)));       // set 1 as padding
    }
    else
    {
        m_state[1] ^= (0x80ull << (56 - (second * 8)));      // set 1 as padding
    }

    // 3. generate authentication tag (same as Finish())
    UINT8 computed_tag[16];
    Finish(computed_tag);

    // 4. verify if provided tag and calculated tag match with each other
    UINT8 diff = 0;
    for ( INT32 i = 0; i < 16; i++ )
    {
        diff |= tag[i] ^ computed_tag[i];
    }
    secure_zero(computed_tag, sizeof(computed_tag)); 

    if ( diff == 0 )
    {
        return TRUE;  // verification succeeded
    }

    // verification failed
    secure_zero(out, cphlen); 
    return FALSE;
}


VOID CAscon128a::Finish(UINT8 tag[16])
{
    // finalize
    // 1. mix state with secret key once again (domain separation)
    m_state[2] ^= m_k0;
    m_state[3] ^= m_k1;

    // 2. last big scramble (replace 12 rounds)
    Permutation(12);

    // 3. final key masking
    m_state[3] ^= m_k0;
    m_state[4] ^= m_k1;

    // 4. output 16-byte authentication tag
    // first 8 bytes (m_state[3])
    Uint64ToBytes(tag, m_state[3]);
    // second 8 bytes (m_state[4])
    Uint64ToBytes(tag + 8, m_state[4]);
}


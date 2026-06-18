/* ========================================================================== */
/**
 * @file    ascon128.cpp
 * @brief   Ascon-128 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "ascon128.h"
#include "secure.h"

VOID CAscon128::Initialize(const UINT8 key[16], const UINT8 nonce[16], const UINT8 * ad, SIZE_T adlen)
{
    // algorithm parameter (Key-length=128, Rate=64, a=12, b=6)
    CAsconAead::Initialize(key, nonce, 0x80400c0600000000ull);

    // process Associated Data
    if ( adlen > 0 )
    {
        // 1. 8-byte (64 bits) block process
        while ( adlen >= 8 )
        {
            // XOR m_state with converted 64-bit data
            m_state[0] ^= BytesToUint64(ad);

            // scramble 6 rounds
            Permutation(6);

            ad += 8;
            adlen -= 8;
        }

        // 2. padding
        UINT64 last_block = BytesToUint64(ad, adlen);

        // set bit at the next position
        last_block |= (0x80ull << (56 - (adlen * 8)));

        m_state[0] ^= last_block;
        Permutation(6);
    }
    // 3. domain separation
    // XOR LSB of state with 1
    m_state[4] ^= 1ull;
}


VOID CAscon128::Encrypt(UINT8 * out, UINT8 tag[16], const UINT8 * message, SIZE_T msglen)
{
    // 1. 8-byte (64 bits) block process
    while ( msglen >= 8 )
    {
        // XOR 0th of m_state with plaintext
        m_state[0] ^= BytesToUint64(message);

        // extract ciphertext from 0th of m_state
        Uint64ToBytes(out, m_state[0]);

        // replace 6 rounds
        Permutation(6);

        message += 8;
        out += 8;
        msglen -= 8;
    }

    // 2. padding
    UINT64 last_block = BytesToUint64(message, msglen);

    // set 1 bit at tail of data
    last_block |= ((UINT64)0x80 << (56 - (msglen * 8)));

    // XOR 0th m_state with padding
    m_state[0] ^= last_block;

    // extract last fragment of cipertext from 0th of m_state
    Uint64ToBytes(out, m_state[0], msglen);

    Finish(tag);
}


BOOL CAscon128::Decrypt(UINT8 * out, const UINT8 * cipher, SIZE_T cphlen, const UINT8 tag[16])
{
    SIZE_T len = cphlen;
    UINT8 * ptr = out;

    // 1. 8-byte (64 bits) block process
    while ( len >= 8 )
    {
        // convert current chipertext block to 64-bit data
        UINT64 c_block = BytesToUint64(cipher);

        // plaintext = m_state[0] ^ ciphertext
        UINT64 block = m_state[0] ^ c_block;

        // store plaintext
        Uint64ToBytes(ptr, block);

        // overwrite state with ciphertext
        m_state[0] = c_block;

        // replace 6 rounds (preparing next block)
        Permutation(6);

        cipher += 8;
        ptr += 8;
        len -= 8;
    }

    // 2. padding
    UINT64 c_last = BytesToUint64(cipher, len);

    // decrypt fragment block: plaintext = state ^ ciphertext
    UINT64 last = m_state[0] ^ c_last;

    // store last fragment
    Uint64ToBytes(ptr, last, len);

    // update state
    m_state[0] &= ((0xffffffffffffffffull >> (len * 8)));   // clear processed bits
    m_state[0] |= c_last;                                   // embed ciphertext
    m_state[0] ^= (0x80ull << (56 - (len * 8)));            // set 1 as padding

    // 3. generate authentication tag (same as Finish())
    UINT8 computed_tag[16];
    Finish(computed_tag);

    // 4. verify if provided tag and calculated tag match with each other
    UINT8 diff = 0;
    for ( INT32 i = 0; i < 16; i++ )
    {
        diff |= tag[i] ^ computed_tag[i];
    }
    if ( diff == 0 )
    {
        return TRUE;  // verification succeeded
    }

    // verification failed
    secure_zero(out, cphlen); 
    return FALSE;
}


VOID CAscon128::Finish(UINT8 tag[16])
{
    // finalize
    // 1. mix state with secret key once again (domain separation)
    m_state[1] ^= m_k0;
    m_state[2] ^= m_k1;

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


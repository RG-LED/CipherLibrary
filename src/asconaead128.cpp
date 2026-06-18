/* ========================================================================== */
/**
 * @file    asconaead128.cpp
 * @brief   Ascon-AEAD128 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "asconaead128.h"
#include "secure.h"

VOID CAsconAead128::Initialize(const UINT8 key[16], const UINT8 nonce[16], const UINT8 * ad, SIZE_T adlen)
{
    // 1. convert key and nonce into 64-bit data
    m_k0 = BytesToUint64(key);
    m_k1 = BytesToUint64(key + 8);
    UINT64 n0 = BytesToUint64(nonce);
    UINT64 n1 = BytesToUint64(nonce + 8);

    // 2. place them in 320-bit state
    m_state[0] = 0x00001000808c0001ull;
    m_state[1] = m_k0;
    m_state[2] = m_k1;
    m_state[3] = n0;
    m_state[4] = n1;

    // 3. first big scramble (replace 12 rounds)
    Permutation(12);

    // 4. XOR tail of state with key again to prevent brute force attack
    m_state[3] ^= m_k0;
    m_state[4] ^= m_k1;

    // process Associated Data
    if ( adlen > 0 )
    {
        // 1. 16-byte (128 bits) block process
        while ( adlen >= 16 )
        {
            // XOR state with two 64-bit data converted from data block
            m_state[0] ^= BytesToUint64(ad);
            m_state[1] ^= BytesToUint64(ad + 8);

            // replace 8 rounds
            Permutation(8);

            ad += 16;
            adlen -= 16;
        }

        // 2. padding
        if ( adlen >= 8 )
        {
            m_state[0] ^= BytesToUint64(ad, 8);
            UINT64 last_block = BytesToUint64(ad + 8, adlen - 8);
            last_block |= (0x01ull << ((adlen - 8) * 8));
            m_state[1] ^= last_block;
        }
        else
        {
            UINT64 last_block = BytesToUint64(ad, adlen);
            last_block |= (0x01ull << (adlen * 8));
            m_state[0] ^= last_block;
        }

        Permutation(8);
    }
    // 3. domain separation
    // XOR MSB of state tail with 1
    m_state[4] ^= 0x8000000000000000ull;
}


VOID CAsconAead128::Encrypt(UINT8 * out, UINT8 tag[16], const UINT8 * message, SIZE_T msglen)
{
    // 1. 16-byte (128 bits) block process
    while ( msglen >= 16 )
    {
        // XOR 0th and 1st state with plaintext
        m_state[0] ^= BytesToUint64(message);
        m_state[1] ^= BytesToUint64(message + 8);

        // extract ciphertext from 0th and 1st state
        Uint64ToBytes(out, m_state[0]);
        Uint64ToBytes(out + 8, m_state[1]);

        // replace 8 rounds
        Permutation(8);

        message += 16;
        out += 16;
        msglen -= 16;
    }

    // 2. padding
    if ( msglen >= 8 )
    {
        m_state[0] ^= BytesToUint64(message, 8);
        UINT64 last_block = BytesToUint64(message + 8, msglen - 8);
        last_block |= (0x01ull << ((msglen - 8) * 8));
        m_state[1] ^= last_block;
        // extract last fragment ciphertext from 0th and 1st m_state
        Uint64ToBytes(out, m_state[0], 8);
        Uint64ToBytes(out + 8, m_state[1], msglen - 8);
    }
    else
    {
        UINT64 last_block = BytesToUint64(message, msglen);
        last_block |= (0x01ull << (msglen * 8));
        m_state[0] ^= last_block;
        // extract last fragment ciphertext from 0th m_state
        Uint64ToBytes(out, m_state[0], msglen);
    }

    Finish(tag);
}


BOOL CAsconAead128::Decrypt(UINT8 * out, const UINT8 * cipher, SIZE_T cphlen, const UINT8 tag[16])
{
    SIZE_T len = cphlen;
    UINT8 * ptr = out;

    // 1. 16-byte (128 bits) block process
    while ( len >= 16 )
    {
        // convert current ciphertext block to 64-bit data
        UINT64 c_block0 = BytesToUint64(cipher);
        UINT64 c_block1 = BytesToUint64(cipher + 8);

        // plaintext = state (m_state[0]) ^ ciphertext
        UINT64 block0 = m_state[0] ^ c_block0;
        UINT64 block1 = m_state[1] ^ c_block1;

        // store plaintext
        Uint64ToBytes(ptr, block0);
        Uint64ToBytes(ptr + 8, block1);

        // replace state with ciphertext
        m_state[0] = c_block0;
        m_state[1] = c_block1;

        // replace 8 rounds (preparing next block)
        Permutation(8);

        cipher += 16;
        ptr += 16;
        len -= 16;
    }

    // 2. padding
    if ( len >= 8 )
    {
        UINT64 c_last0 = BytesToUint64(cipher, 8);
        UINT64 c_last1 = BytesToUint64(cipher + 8, len - 8);
        UINT64 last0 = m_state[0] ^ c_last0;
        UINT64 last1 = m_state[1] ^ c_last1;
        Uint64ToBytes(ptr, last0, 8);
        Uint64ToBytes(ptr + 8, last1, len - 8);
        m_state[0] = c_last0;
        m_state[1] &= ((0xffffffffffffffffull << ((len - 8) * 8))); // clear processed bits
        m_state[1] |= c_last1;                                      // embed ciphertext
        m_state[1] ^= (0x01ull << ((len - 8) * 8));                 // set 1 as padding
    }
    else
    {
        UINT64 c_last = BytesToUint64(cipher, len);
        UINT64 last = m_state[0] ^ c_last;
        Uint64ToBytes(ptr, last, len);
        m_state[0] &= ((0xffffffffffffffffull << (len * 8))); // clear processed bits
        m_state[0] |= c_last;                                 // embed ciphertext
        m_state[0] ^= (0x01ull << (len * 8));                 // set 1 as padding
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
    if ( diff == 0 )
    {
        return TRUE;  // verification succeeded
    }

    // verification failed
    secure_zero(out, cphlen); 
    return FALSE;
}


VOID CAsconAead128::Finish(UINT8 tag[16])
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


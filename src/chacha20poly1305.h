/* ========================================================================== */
/**
 * @file    chacha20poly1305.h
 * @brief   ChaCha20-Poly1305 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_CHACHA20POLY1305_H_)
#define _CHACHA20POLY1305_H_

#include "chacha20.h"
#include "poly1305.h"

class CChacha20Poly1305
{
public:
    CChacha20Poly1305();
    ~CChacha20Poly1305();
    VOID Initialize(const UINT8 key[32], const UINT8 nonce[12]);
    VOID UpdateAad(const UINT8 * aad, SIZE_T len);
    VOID Encrypt(UINT8 * out, const UINT8 * in, SIZE_T len);
    VOID Finish(UINT8 tag[16]);
    BOOL VerifyAndDecrypt(UINT8 * out, const UINT8 * in, SIZE_T len, const UINT8 tag[16]);

private:
    VOID Padding16(UINT64 len);

    CChacha20 m_chacha;
    CPoly1305 m_poly;
    UINT64 m_aadLen;
    UINT64 m_dataLen;

    enum State {
        ST_INIT,
        ST_AAD,
        ST_DATA,
        ST_FINAL
    } m_state;

};

#endif // #if !defined(_CHACHA20POLY1305_H_)


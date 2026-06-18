/* ========================================================================== */
/**
 * @file    xchacha20poly1305.h
 * @brief   XChaCha20-Poly1305 cipher class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_XCHACHA20POLY1305_H_)
#define _XCHACHA20POLY1305_H_

#include "xchacha20.h"
#include "poly1305.h"

class CXChacha20Poly1305
{
public:
    CXChacha20Poly1305();
    ~CXChacha20Poly1305();
    VOID Initialize(const UINT8 key[32], const UINT8 nonce[24]);
    VOID UpdateAad(const UINT8 * aad, SIZE_T len);
    VOID Encrypt(UINT8 * out, const UINT8 * in, SIZE_T len);
    VOID Finish(UINT8 tag[16]);
    BOOL VerifyAndDecrypt(UINT8 * out, const UINT8 * in, SIZE_T len, const UINT8 tag[16]);

private:
    VOID Padding16(UINT64 len);

    CXChacha20 m_xchacha;
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

#endif // #if !defined(_XCHACHA20POLY1305_H_)


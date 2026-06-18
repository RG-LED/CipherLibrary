/* ========================================================================== */
/**
 * @file    hmacsha256.h
 * @brief   HMAC-SHA256 hash class for PBKDF2
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_HMACSHA256_H_)
#define _HMACSHA256_H_

#include "sha256.h"

class CHmacSha256
{
public:
    VOID Initialize(const UINT8 key[], SIZE_T len);
    VOID Update(const UINT8 * msg, SIZE_T len);
    VOID Finish(UINT8 * hash);

private:
    CSha256 m_iSha;
    CSha256 m_oSha;
};

#endif // #if !defined(_HMACSHA256_H_)


/* ========================================================================== */
/**
 * @file    pbkdf2.h
 * @brief   PBKDF2 key derivation class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_PBKDF2_H_)
#define _PBKDF2_H_

#include "sha256.h"

class CPbkdf2
{
public:
    VOID Prepare(const UINT8 key[], SIZE_T len);
    VOID Iteration(const UINT8 * salt, SIZE_T len, UINT32 iter, UINT32 idx, UINT8 * out);

private:
    CSha256 m_iSha;
    CSha256 m_oSha;
};

#endif // #if !defined(_PBKDF2_H_)


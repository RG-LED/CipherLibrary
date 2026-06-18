/* ========================================================================== */
/**
 * @file    Sha256.h
 * @brief   SHA-256 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_SHA256_H_)
#define _SHA256_H_

#include "BasicDefs.h"

#define SHA256_BUFFER_SIZE 64

/* ========================================================================== */
/**
 * SHA-256 hash class
 */
/* ========================================================================== */

class CSha256
{
////////////////////////////////////////
// PUBLIC
////////////////////////////////////////
public:
    CSha256() { Initialize(); }
    ~CSha256();
    VOID Initialize(VOID);
    VOID Update(const UINT8 * data, SIZE_T len);
    VOID Finish(UINT8 hash[32]);

    static constexpr SIZE_T BlockSize = 64;
    static constexpr SIZE_T OutputSize = 32;

////////////////////////////////////////
// PROTECTED
////////////////////////////////////////
protected:

////////////////////////////////////////
// PRIVATE
////////////////////////////////////////
private:
    VOID CalculateHash(const UINT8 * data);
    VOID UpdateHash(const UINT32 w[64]);
    UINT8 m_Buffer[SHA256_BUFFER_SIZE];
    SIZE_T m_BufLen;
    UINT64 m_Len;
    UINT32 m_H[8];
};

#endif /* #if !defined(_SHA256_H_) */

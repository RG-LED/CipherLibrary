/* ========================================================================== */
/**
 * @file    Sha512base.h
 * @brief   SHA-384/512 hash base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_SHA512BASE_H_)
#define _SHA512BASE_H_

#include "BasicDefs.h"

#define SHA512_BUFFER_SIZE 128

/* ========================================================================== */
/**
 * SHA-385/512 hash base class
 */
/* ========================================================================== */

class CSha512Base
{
////////////////////////////////////////
// PUBLIC
////////////////////////////////////////
public:
    VOID Update(const UINT8 * data, SIZE_T len);

////////////////////////////////////////
// PROTECTED
////////////////////////////////////////
protected:
    ~CSha512Base();
    VOID Initialize(const UINT64 iv[8]);
    VOID Finish();

    UINT64 m_H[8];

////////////////////////////////////////
// PRIVATE
////////////////////////////////////////
private:
    VOID Initialize();
    VOID CalculateHash(const UINT8 * data);
    VOID UpdateHash(const UINT64 w[80]);

    UINT8 m_Buffer[SHA512_BUFFER_SIZE];
    SIZE_T m_BufLen;
    UINT64 m_Len;
};

#endif /* #if !defined(_SHA512BASE_H_) */


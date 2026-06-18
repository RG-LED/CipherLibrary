/* ========================================================================== */
/**
 * @file    sha1.h
 * @brief   SHA-1 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_SHA1_H_)
#define _SHA1_H_

#include "BasicDefs.h"

class CSha1
{
public:
    CSha1();
    ~CSha1();
    VOID Initialize();
    VOID Update(const UINT8 * data, SIZE_T len);
    VOID Finish(UINT8 hash[32]);

    static const SIZE_T BlockSize = 64;
    static const SIZE_T OutputSize = 20;

private:
    VOID Transform();

    UINT32 m_h[5];
    UINT64 m_len;
    UINT8  m_buf[64];
    SIZE_T m_bufLen;
};

#endif // _SHA1_H_


/* ========================================================================== */
/**
 * @file    md5.h
 * @brief   MD5 message digest class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_MD5_H_)
#define _MD5_H_

#include "BasicDefs.h"

#define MD5_DIGEST_SIZE 16

/*-----------------------------------------------------------------------------
 *  refer to RFC1321 "MD5 Message-Digest Algorithm"
 *---------------------------------------------------------------------------*/

class CMd5
{
////////////////////////////////////////
// PUBLIC
////////////////////////////////////////
public:
    CMd5() { Initialize(); }
    CMd5(const UINT8 * ptr);
    ~CMd5() { Initialize(); }

    VOID Initialize(VOID);
    VOID Update(const UINT8 * ptr, SIZE_T len) { m_Work.Update(ptr, len); }
    VOID Finish(UINT8 * ptr) { m_Work.Finalize(m_abyDigest); GetDigest(ptr); }

    VOID SetDigest(const UINT8 * ptr) { memcpy(m_abyDigest, ptr, sizeof(m_abyDigest)); }
    VOID GetDigest(UINT8 * ptr) const { memcpy(ptr, m_abyDigest, sizeof(m_abyDigest)); }
    CMd5 & operator=(const UINT8 * ptr);

////////////////////////////////////////
// PROTECTED
////////////////////////////////////////
protected:
////////////////////////////////////////
// PRIVATE
////////////////////////////////////////
private:
    class CMd5Work
    {
    public:
        ~CMd5Work();

        VOID Initialize(VOID);
        VOID Update(const UINT8 * input, SIZE_T inputLen);
        VOID Finalize(UINT8 digest[16]);

    private:
        VOID Transform(UINT32 state[4], const UINT8 block[64]);
        VOID Encode(UINT8 * output, const UINT32 * input, SIZE_T len);
        VOID Decode(UINT32 * output, const UINT8 * input, SIZE_T len);

        UINT32 m_adwState[4];      /* state (ABCD) */
        UINT32 m_adwCount[2];      /* number of bits, modulo 2^64 (lsb first) */
        UINT8 m_abyBuffer[64];   /* input buffer */

        static const UINT8 m_abyPadding[64];
    };

    CMd5Work m_Work;
    UINT8 m_abyDigest[16];
};

#endif /* #if !defined(_MD5_H_) */


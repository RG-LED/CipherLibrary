/* ========================================================================== */
/**
 * @file    asn1decode.h
 * @brief   ASN.1 DER decode class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASN1DECODE_H_)
#define _ASN1DECODE_H_

#include "asn1base.h"

class CAsn1Decoder : public CAsn1Base
{
public:
    static constexpr INT32 MAX_DEPTH = 16;

    CAsn1Decoder();
    VOID Initialize(const UINT8 * top, SIZE_T len);
    BOOL Next(BOOL diveInner = FALSE);
    Asn1Tag GetTag() const { return m_tag; }
    BOOL GetContents(const UINT8 ** ptr, SIZE_T * len) const;
    INT32 GetDepth() const { return m_depth; }
    INT32 GetPosition() const { return m_position[m_depth]; }
    VOID GetPosition(CHAR8 pos[MAX_DEPTH + 1]) const;
    const UINT8 * GetCurrentPointer() { return m_top; }

private:
    BOOL FetchElement();

    Asn1Tag m_tag;
    const UINT8 * m_top;
    const UINT8 * m_content;
    SIZE_T m_size;
    INT32 m_depth;
    INT32 m_position[MAX_DEPTH];
    const UINT8 * m_end[MAX_DEPTH];
};

#endif /* #if !defined(_ASN1DECODE_H_) */


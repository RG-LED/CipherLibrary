/* ========================================================================== */
/**
 * @file    asn1encode.h
 * @brief   ASN.1 DER encode class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASN1ENCODE_H_)
#define _ASN1ENCODE_H_

#include "asn1base.h"

class CAsn1Encoder : public CAsn1Base
{
public:
    CAsn1Encoder();
    VOID Initialize(UINT8 * top, SIZE_T len);
    BOOL PutElement(Asn1Tag tag, const UINT8 * data, SIZE_T size);
    BOOL StartConstructed(Asn1Tag tag);
    BOOL EndConstructed();
    SIZE_T Finish();

private:
    BOOL PutSize(UINT8 * & ptr, SIZE_T size);
    static SIZE_T SizeField(SIZE_T size);

    static constexpr INT32 MAX_DEPTH = 16;

    UINT8 * m_top;
    UINT8 * m_pointer;
    UINT8 * m_end;
    INT32 m_depth;
    UINT8 * m_sizePtr[MAX_DEPTH];
};

#endif /* #if !defined(_ASN1ENCODE_H_) */


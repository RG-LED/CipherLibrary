/* ========================================================================== */
/**
 * @file    asn1base.h
 * @brief   ASN.1 DER base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASN1BASE_H_)
#define _ASN1BASE_H_

#include "BasicDefs.h"

class CAsn1Base
{
public:
    enum Asn1Tag
    {
        None = 0x00,
        Boolean = 0x01,
        Integer = 0x02,
        BitString = 0x03,
        OctetString = 0x04,
        Null = 0x05,
        ObjectIdentifier = 0x06,
        Real = 0x09,
        Enumerated = 0x0a,
        UTF8String = 0x0c,
        RelativeOID = 0x0d,
        Time = 0x0e,
        PrintableString = 0x13,
        T61String = 0x14,
        IA5String = 0x16,
        UTCTime = 0x17,
        GeneralizedTime = 0x18,
        VisibleString = 0x1a,
        GeneralString = 0x1b,
        BMPString = 0x1e,
        Sequence = 0x30, // 0x10 | Constructed
        Set = 0x31, // 0x11 | Constructed
        Constructed = 0x20,
        Application = 0x40,
        ContextSpecific = 0x80,
        Private = 0xc0,
    };
};

#endif /* #if !defined(_ASN1BASE_H_) */


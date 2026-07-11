/* ========================================================================== */
/**
 * @file    tls13.cpp
 * @brief   TLS 1.3 message handling client class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "tls13.h"
#include "x25519.h"
#include "ecdh.h"
#include "hkdf.h"
#include "rsa2048.h"
#include "ecdsa.h"
#include "ed25519.h"
#include "hmac.h"
#include "secure.h"

#if USE_CHACHA20POLY1305
#include "chacha20poly1305.h"
#else
#include "aesgcm.h"
#endif

#define READ16(p)       (((p)[0] << 8) | (p)[1])
#define READ24(p)       (((p)[0] << 16) | ((p)[1] << 8) | (p)[2])
#define WRITE16(p, n)   { (p)[0] = (UINT8)((n) >> 8); (p)[1] = (UINT8)(n); }
#define WRITE24(p, n)   { (p)[0] = (UINT8)((n) >> 16); (p)[1] = (UINT8)((n) >> 8); (p)[2] = (UINT8)(n); }

/* Alert */
/* Alert level */
#define ALERT_WARNING   1
#define ALERT_FATAL     2

/* Alert description */
#define ALERT_UNEXPECTED_MESSAGE    10
#define ALERT_BAD_RECORD_MAC        20
#define ALERT_ILLEGAL_PARAMETER     47
#define ALERT_DECODE_ERROR          50
#define ALERT_DECRYPT_ERROR         51
#define ALERT_PROTOCOL_VERSION      70
#define ALERT_INTERNAL_ERROR        80

CTls13::~CTls13()
{
    secure_zero(m_privateKey, sizeof(m_privateKey));
    secure_zero(m_clientPublicKey, sizeof(m_clientPublicKey));
    secure_zero(m_serverPublicKey, sizeof(m_serverPublicKey));
    secure_zero(m_sharedSecret, sizeof(m_sharedSecret));
    secure_zero(m_derivedSecret, sizeof(m_derivedSecret));

    secure_zero(m_clientKey, sizeof(m_clientKey));
    secure_zero(m_clientIV, sizeof(m_clientIV));
    secure_zero(m_serverKey, sizeof(m_serverKey));
    secure_zero(m_serverIV, sizeof(m_serverIV));

    secure_zero(m_cookie, sizeof(m_cookie));
    secure_zero(m_certPublicKey1, sizeof(m_certPublicKey1));
    secure_zero(m_certPublicKey2, sizeof(m_certPublicKey2));
    secure_zero(m_serverFinishedKey, sizeof(m_serverFinishedKey));
    secure_zero(m_clientFinishedKey, sizeof(m_clientFinishedKey));
}


VOID CTls13::Reset()
{
    m_phase = SendingClientHello;
    m_keyExchange = Secp256r1; // X25519;
    m_transHash.Initialize();
}


#pragma pack(push, 1)

struct RecordHeader
{
    UINT8 ContentType;
    UINT8 ProtocolVersion[2];
    UINT8 RecordLength[2];
};

struct HandshakeHeader
{
    UINT8 HandshakeType;
    UINT8 HandshakeLength[3];
};

struct HelloHeader
{
    UINT8 ProtocolVersion[2];
    UINT8 Random[32];
};

struct PacketHeader
{
    RecordHeader    Record;
    HandshakeHeader Handshake;
    union
    {
        HelloHeader Hello;
        UINT8       MessageBody[1];
    };
};

#pragma pack(pop)


BOOL CTls13::StartConnection(TLS_CALLBACK receiver, TLS_CALLBACK sender, UINT32 id)
{
    m_receiverFunc = receiver;
    m_senderFunc = sender;
    m_callbackID = id;

    Reset();

    return SendClientHello();
}


BOOL CTls13::SendClientHello()
{
    UINT8 msg[384];
    SIZE_T len = sizeof(msg);

    if ( !MakeClientHello(msg, len) )
    {
        secure_zero(msg, sizeof(msg));
        return FALSE;
    }
    if ( m_senderFunc != NULL )
    {
        (*m_senderFunc)(m_callbackID, msg, len);
    }

    secure_zero(msg, sizeof(msg));
    return TRUE;
}


BOOL CTls13::SendClientFinished()
{
    UINT8 msg[64];
    SIZE_T len = sizeof(msg);

    if ( !MakeClientFinished(msg, len) )
    {
        secure_zero(msg, sizeof(msg));
        return FALSE;
    }
    if ( m_senderFunc != NULL )
    {
        (*m_senderFunc)(m_callbackID, msg, len);
    }

    secure_zero(msg, sizeof(msg));
    return TRUE;
}


BOOL CTls13::SendAlert(INT32 level, INT32 desc)
{
    UINT8 msg[32];
    SIZE_T len = sizeof(msg);

    PacketHeader * pk = (PacketHeader *)msg;

    pk->Record.ContentType = 0x15;              // Alert
    pk->Record.ProtocolVersion[0] = 0x03;       // LegacyRecordVersion
    pk->Record.ProtocolVersion[1] = 0x03;
    pk->Record.RecordLength[0] = 0x00;
    pk->Record.RecordLength[1] = 0x02;

    msg[sizeof(RecordHeader)] = (UINT8)level;
    msg[sizeof(RecordHeader) + 1] = (UINT8)desc;

    if ( m_phase >= ReceivingServerHello )
    {
        pk->Record.ContentType = 0x16;              // Handshake
        msg[sizeof(RecordHeader) + 2] = 0x15;       // Alert
        EncryptPacket(msg, sizeof(RecordHeader) + 3);
    }

    if ( m_senderFunc != NULL )
    {
        (*m_senderFunc)(m_callbackID, msg, len);
    }

    if ( level == ALERT_FATAL )
    {
        m_phase = Error;
    }

    secure_zero(msg, sizeof(msg));

    return TRUE;
}


BOOL CTls13::MakeClientHello(UINT8 * msg, SIZE_T & len)
{
    static const UINT8 tmpl1[] = {
                        // legacy session ID
        0x00,           //   length (no ID)
                        // cipher suites
        0x00, 0x02,     //   length
#if USE_CHACHA20POLY1305
        0x13, 0x03,     //   TLS_CHACHA20_POLY1305_SHA256
#else
        0x13, 0x01,     //   TLS_AES_128_GCM_SHA256
#endif
                        // compression methods
        0x01,           //   length
        0x00            //   null
    };
    static const UINT8 tmpl2[] = {
                        //   extension #1 (7 bytes)
        0x00, 0x2b,     //     supported version
        0x00, 0x03,     //     length
        0x02,           //     versions length
        0x03, 0x04      //     TLS 1.3
    };
    static const UINT8 tmpl3_x25519[] = {
                        //   extension #2
        0x00, 0x33,     //     key share
        0x00, 0x26,     //     length = 38 (= 2 + 36)
        0x00, 0x24,     //     client_shares_length = 36
        0x00, 0x1d,     //     group = x25519
        0x00, 0x20      //     key_exchange_length = 32
    };
    static const UINT8 tmpl3_secp256r1[] = {
                        //   extension #2
        0x00, 0x33,     //     key share
        0x00, 0x47,     //     length = 71 (= 2 + 69)
        0x00, 0x45,     //     client_shares_length = 69
        0x00, 0x17,     //     group = secp256r1
        0x00, 0x41      //     key_exchange_length = 65
    };
    static const UINT8 tmpl4[] = {
                        //   extension #3
        0x00, 0x0a,     //     supported_groups
        0x00, 0x06,     //     length = 6 (= 2 + 4)
        0x00, 0x04,     //     named group list length = 4
        0x00, 0x17,     //     secp256r1
        0x00, 0x1d,     //     x25519
                        //   extension #4
        0x00, 0x0d,     //     signature_algorithms
        0x00, 0x08,     //     length = 6 (= 2 + 4)
        0x00, 0x06,     //     list length = 4
        0x08, 0x04,     //     rsa_pss_rsae_sha256
        0x04, 0x03,     //     ecdsa_secp256r1_sha256
        0x08, 0x07      //     ed25519
    };

    if ( m_phase != SendingClientHello ||
         len < sizeof(PacketHeader) + sizeof(tmpl1) + sizeof(tmpl2) + 2 /* extension length */ +
               ( m_keyExchange == X25519 ? sizeof(tmpl3_x25519) + X25519_PB_KEYSIZE
                                         : sizeof(tmpl3_secp256r1) + SECP256_PB_KEYSIZE) +
               sizeof(tmpl4) )
    {
        SendAlert(ALERT_FATAL, ALERT_INTERNAL_ERROR);
        return FALSE;
    }

    PacketHeader * pk = (PacketHeader *)msg;
    pk->Record.ContentType = 0x16;              // Handshake
    pk->Record.ProtocolVersion[0] = 0x03;       // LegacyRecordVersion
    pk->Record.ProtocolVersion[1] = 0x03;
    pk->Record.RecordLength[0] = 0;             // temporarily
    pk->Record.RecordLength[1] = 0;
    pk->Handshake.HandshakeType = 0x01;         // ClientHello
    pk->Handshake.HandshakeLength[0] = 0;       // temporarily
    pk->Handshake.HandshakeLength[1] = 0;
    pk->Handshake.HandshakeLength[2] = 0;
    pk->Hello.ProtocolVersion[0] = 0x03;        // TLS 1.2
    pk->Hello.ProtocolVersion[1] = 0x03;
    secure_random(pk->Hello.Random, sizeof(pk->Hello.Random));

    SIZE_T offset = sizeof(*pk);

    memcpy(&msg[offset], tmpl1, sizeof(tmpl1));
    offset += sizeof(tmpl1);

    UINT8 * extlen = &msg[offset];
    offset += 2; // skip extensions length
    UINT8 * extension = &msg[offset];

    memcpy(&msg[offset], tmpl2, sizeof(tmpl2));
    offset += sizeof(tmpl2);

    switch ( m_keyExchange )
    {
        case X25519:
            memcpy(&msg[offset], tmpl3_x25519, sizeof(tmpl3_x25519));
            offset += sizeof(tmpl3_x25519);
            secure_random(m_privateKey, X25519_PV_KEYSIZE);
            CX25519::PrivateKeyToPublicKey(m_clientPublicKey, m_privateKey);
            memcpy(&msg[offset], m_clientPublicKey, X25519_PB_KEYSIZE);
            offset += X25519_PB_KEYSIZE;
            break;

        case Secp256r1:
            memcpy(&msg[offset], tmpl3_secp256r1, sizeof(tmpl3_secp256r1));
            offset += sizeof(tmpl3_secp256r1);
            do
            {
                secure_random(m_privateKey, SECP256_PV_KEYSIZE);
            }
            while ( !CEcdh<EcCurve::P256>::PrivateKeyToPublicKey(m_clientPublicKey, m_privateKey) );
            memcpy(&msg[offset], m_clientPublicKey, SECP256_PB_KEYSIZE);
            offset += SECP256_PB_KEYSIZE;
            break;

        default:
            SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
            return FALSE;
    }

    memcpy(&msg[offset], tmpl4, sizeof(tmpl4));
    offset += sizeof(tmpl4);

    SIZE_T n = &msg[offset] - extension;

    WRITE16(extlen, n);
    extlen[1] = (UINT8)n;

    n = &msg[offset] - (UINT8 *)&pk->Hello;
    WRITE24(pk->Handshake.HandshakeLength, n);

    n = &msg[offset] - (UINT8 *)&pk->Handshake;
    WRITE16(pk->Record.RecordLength, n);

    len = offset;
    m_phase = ReceivingServerHello;
    m_transHash.Update(msg + sizeof(RecordHeader), len - sizeof(RecordHeader));

    return TRUE;
}


BOOL CTls13::MakeClientFinished(UINT8 * msg, SIZE_T & len)
{
    PacketHeader * pk = (PacketHeader *)msg;
    if ( m_phase != SendingFinished ||
         &msg[len] < &pk->MessageBody[HASH_SIZE + 1] + TAG_SIZE )
    {
        SendAlert(ALERT_FATAL, ALERT_INTERNAL_ERROR);
        return FALSE;
    }

    UINT8 hash[HASH_SIZE];
    CSha256 sha = m_transHash;
    CHmac<CSha256> hmac;

    sha.Finish(hash);
    hmac.Initialize(m_clientFinishedKey, sizeof(m_clientFinishedKey));
    hmac.Update(hash, sizeof(hash));
    hmac.Finish(hash);

    pk->Record.ContentType = 0x17;              // ApplicationData
    pk->Record.ProtocolVersion[0] = 0x03;       // LegacyRecordVersion
    pk->Record.ProtocolVersion[1] = 0x03;
    pk->Record.RecordLength[0] = 0x00;          // size
    pk->Record.RecordLength[1] = 0x25 + TAG_SIZE; // 5 + 32 + 1 + 16
    pk->Handshake.HandshakeType = 0x14;         // Finished(client)
    pk->Handshake.HandshakeLength[0] = 0x00;    // size
    pk->Handshake.HandshakeLength[1] = 0x00;
    pk->Handshake.HandshakeLength[2] = 0x20;
    memcpy(pk->MessageBody, hash, sizeof(hash));
    pk->MessageBody[sizeof(hash)] = 0x16;       // Handshake

    len = sizeof(RecordHeader) + 0x25;

    sha = m_transHash;
    sha.Finish(hash);

    m_transHash.Update(msg + sizeof(RecordHeader), len - sizeof(RecordHeader) - 1);

    EncryptPacket(msg, len);

    len += TAG_SIZE;

    PrepareEncryption2(hash);

    m_phase = Connected;

    secure_zero(hash, sizeof(hash));

    return TRUE;
}


BOOL CTls13::ProcessReceivedMessage(UINT8 * msg, SIZE_T & len)
{
    UINT8 * p = msg;

    while ( len > sizeof(RecordHeader) )
    {
        PacketHeader * pk = (PacketHeader *)p;
        if ( pk->Record.ProtocolVersion[0] != 0x03 ||   // LegacyRecordVersion
             pk->Record.ProtocolVersion[1] != 0x03 )
        {
            SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
            return FALSE;
        }

        SIZE_T size = READ16(pk->Record.RecordLength) + sizeof(RecordHeader);

        if ( size > len )
        {
            break;
        }

        SIZE_T contents = size;

    Retry:
        switch ( pk->Record.ContentType )
        {
            case 0x14:  // ChangeCipherSpec (TLS 1.2)
                if ( p[sizeof(RecordHeader)] != 0x01 )
                {
                    SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
                    return FALSE;
                }
                break;

            case 0x15:  // Alert
                if ( p[sizeof(RecordHeader)] == 0x01 &&     // warning
                     p[sizeof(RecordHeader) + 1] == 0x00 )  // close_notify
                {
                    m_phase = Closed;
                }
                else
                {
                    m_phase = Error;
                }
                return FALSE;

            case 0x16:  // Handshake
                if ( !ProcessHandshake(p, contents) )
                {
                    return FALSE;
                }
                break;

            case 0x17:  // ApplicationData
                if ( size <= sizeof(RecordHeader) + TAG_SIZE )
                {
                    SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
                    return FALSE;
                }
                if ( !DecryptPacket(p, size) )
                {
                    SendAlert(ALERT_FATAL, ALERT_BAD_RECORD_MAC);
                    return FALSE;
                }
                contents -= TAG_SIZE + 1;
                while ( contents >= sizeof(RecordHeader) && p[contents] == 0x00 )
                {
                    contents--;
                }
                if ( p[contents] != 0x17 )  // ApplicationData
                {
                    pk->Record.ContentType = p[contents];
                    goto Retry;
                }
                if ( m_receiverFunc != NULL )
                {
                    (*m_receiverFunc)(m_callbackID, p + sizeof(RecordHeader), contents - sizeof(RecordHeader));
                }
                break;

            default:
                SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
                return FALSE;
        }

        p += size;
        len -= size;
    }
    if ( len > 0 )
    {
        memcpy(msg, p, len);
    }
    if ( m_phase == SendingFinished )
    {
        return SendClientFinished();
    }
    return TRUE;
}


BOOL CTls13::ProcessHandshake(const UINT8 * msg, SIZE_T len)
{
    const PacketHeader * pk = (PacketHeader *)msg;
    switch ( pk->Handshake.HandshakeType )
    {
        case 0x02:  // ServerHello
            if ( !ParseServerHello(msg, len) )
            {
                return FALSE;
            }
            m_transHash.Update(msg + sizeof(RecordHeader), len - sizeof(RecordHeader));
            PrepareEncryption();
            break;

        case 0x08:  // EncryptedExtensions
            if ( !ParseEncryptedExtension(msg, len) )
            {
                return FALSE;
            }
            m_transHash.Update(msg + sizeof(RecordHeader), len - sizeof(RecordHeader));
            break;

        case 0x0b:  // Certificate
            if ( !ParseCertificate(msg, len) )
            {
                return FALSE;
            }
            m_transHash.Update(msg + sizeof(RecordHeader), len - sizeof(RecordHeader));
            break;

        case 0x0d:  // CertificateRequest
            SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
            return FALSE;   // This implementation does not support client certification

        case 0x0f:  // CertificateVerify
            if ( !ParseCertificateVerify(msg, len) )
            {
                return FALSE;
            }
            m_transHash.Update(msg + sizeof(RecordHeader), len - sizeof(RecordHeader));
            break;

        case 0x14:  // Finished
            if ( !ParseFinished(msg, len) )
            {
                return FALSE;
            }
            m_transHash.Update(msg + sizeof(RecordHeader), len - sizeof(RecordHeader));
            break;

        case 0x04:  // NewSessionTicket
            break;

        default:
            SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
            return FALSE;
    }
    return TRUE;
}

BOOL CTls13::BuildPacket(UINT8 * out, SIZE_T & len, const VOID * msg, SIZE_T msglen)
{
    PacketHeader * pk = (PacketHeader *)out;

    SIZE_T n = sizeof(RecordHeader) + msglen + 1 + TAG_SIZE;
    if ( len < n )
    {
        SendAlert(ALERT_FATAL, ALERT_INTERNAL_ERROR);
        return FALSE;
    }

    pk->Record.ContentType = 0x17;              // ApplicationData
    pk->Record.ProtocolVersion[0] = 0x03;       // LegacyRecordVersion
    pk->Record.ProtocolVersion[1] = 0x03;

    memcpy(&out[sizeof(RecordHeader)], msg, msglen);
    out[sizeof(RecordHeader) + msglen] = 0x17;           // ApplicationData

    n = msglen + 1 + TAG_SIZE;
    pk->Record.RecordLength[0] = (UINT8)(n >> 8);
    pk->Record.RecordLength[1] = (UINT8)n;

    len = sizeof(RecordHeader) + msglen + 1;
    EncryptPacket(out, len);

    len += TAG_SIZE;

    return TRUE;
}


BOOL CTls13::ParseServerHello(const UINT8 * msg, SIZE_T len)
{
    static const UINT8 HelloRetryRequest[] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
    };

    if ( m_phase != ReceivingServerHello )
    {
        SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return FALSE;
    }

    if ( len < sizeof(PacketHeader) + 1 )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return FALSE;
    }

    const PacketHeader * pk = (const PacketHeader *)msg;

    if ( pk->Hello.ProtocolVersion[0] != 0x03 ||        // TLS 1.2
         pk->Hello.ProtocolVersion[1] != 0x03 )
    {
        SendAlert(ALERT_FATAL, ALERT_PROTOCOL_VERSION);
        return FALSE;
    }

    BOOL retry = (memcmp(pk->Hello.Random, HelloRetryRequest, sizeof(pk->Hello.Random)) == 0);

    SIZE_T offset = sizeof(*pk);

    if ( len < sizeof(PacketHeader) )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return FALSE;
    }

    SIZE_T n = msg[offset++];   // legacy session ID length
    offset += n;    // skip legacy session ID
    offset += 2;    // skip cipher suite
    offset++;       // skip compression method

    if ( len < offset + 2 )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return FALSE;
    }

    INT32 extlen = READ16(&msg[offset]);  // extensions length
    offset += 2;        // skip it

    if ( len < offset + extlen )
    {
        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
        return FALSE;
    }

    const UINT8 * extension = &msg[offset];

    BOOL gotSupportedVersion = FALSE;
    BOOL gotKeyshare = FALSE;

    while ( extlen > 4 )    // type (2 bytes) and length (2 bytes) at least
    {
        UINT32 exttype = READ16(extension);
        extension += 2;
        extlen -= 2;
        INT32 size = READ16(extension);
        extension += 2;
        extlen -= 2;

        switch ( exttype )
        {
            case 0x002b:    // supported version
                if ( size != 2 || extlen < 2 || READ16(extension) != 0x0304 )
                {
                    SendAlert(ALERT_FATAL, ALERT_PROTOCOL_VERSION);
                    return FALSE;
                }
                extension += 2;
                extlen -= 2;
                gotSupportedVersion = TRUE;
                break;

            case 0x0033:    // key share
                if ( retry )
                {
                    UINT32 group = READ16(extension);
                    extension += 2;
                    extlen -= 2;
                    switch ( group )
                    {
                        case 0x0017:    // secp256r1
                            m_keyExchange = Secp256r1;
                            break;
                        case 0x001d:    // x25519
                            m_keyExchange = X25519;
                            break;
                        default:
                            SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
                            return FALSE;
                    }
                    gotKeyshare = TRUE;
                }
                else
                {
                    if ( size < HASH_SIZE + 2 + 2 || extlen < size )
                    {
                        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
                        return FALSE;
                    }
                    UINT32 group = READ16(extension);
                    extension += 2;
                    INT32 keylen = READ16(extension);
                    extension += 2;
                    extlen -= 4;
                    if ( extlen < keylen )
                    {
                        SendAlert(ALERT_FATAL, ALERT_DECODE_ERROR);
                        return FALSE;
                    }
                    switch ( group )
                    {
                        case 0x0017:    // secp256r1
                            if ( keylen != SECP256_PB_KEYSIZE )
                            {
                                SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
                                return FALSE;
                            }
                            memcpy(m_serverPublicKey, extension, SECP256_PB_KEYSIZE);
                            extension += SECP256_PB_KEYSIZE;
                            extlen -= SECP256_PB_KEYSIZE;
                            m_keyExchange = Secp256r1;
                            gotKeyshare = TRUE;
                            break;

                        case 0x001d:    // x25519
                            if ( keylen != X25519_PB_KEYSIZE )
                            {
                                SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
                                return FALSE;
                            }
                            memcpy(m_serverPublicKey, extension, X25519_PB_KEYSIZE);
                            extension += X25519_PB_KEYSIZE;
                            extlen -= X25519_PB_KEYSIZE;
                            m_keyExchange = X25519;
                            gotKeyshare = TRUE;
                            break;

                        default:
                            SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
                            return FALSE;
                    }
                }
                break;

            default:
                extension += size;
                extlen -= size;
                break;
        }
    }

    if ( retry )
    {
        UINT8 hash[HASH_SIZE];
        m_transHash.Finish(hash);
        m_transHash.Initialize();
        m_transHash.Update((const UINT8 *)"\xfe\x00\x00\x00", 4);
        m_transHash.Update(hash, sizeof(hash));

        m_phase = SendingClientHello;

        secure_zero(hash, sizeof(hash));

        return SendClientHello();
    }
    else if ( !gotSupportedVersion || !gotKeyshare )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }

    m_phase = ReceivingEncryptedExtensions;

    return TRUE;
}


BOOL CTls13::ParseEncryptedExtension(const UINT8 * msg, SIZE_T len)
{
    if ( m_phase != ReceivingEncryptedExtensions )
    {
        SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return FALSE;
    }

    const PacketHeader * pk = (const PacketHeader *)msg;

    if ( msg + len < &pk->MessageBody[2] )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }

    INT32 extlen = READ16(pk->MessageBody);    // extensions length

    const UINT8 * extension = &pk->MessageBody[2];

    if ( msg + len < extension + extlen )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }

    while ( extlen > 4 )    // type (2 bytes) and length (2 bytes) at least
    {
        UINT32 exttype = READ16(extension);
        extension += 2;
        extlen -= 2;
        INT32 size = READ16(extension);
        extension += 2;
        extlen -= 2;

        switch ( exttype )
        {
            case 0x000a:    // supported groups
                extension += size;
                extlen -= size;
                break;

            default:
                extension += size;
                extlen -= size;
                break;
        }
    }

    m_phase = ReceivingCertificate;

    return TRUE;
}


BOOL CTls13::ParseCertificate(const UINT8 * msg, SIZE_T len)
{
    if ( m_phase != ReceivingCertificate )
    {
        SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return FALSE;
    }

    const PacketHeader * pk = (const PacketHeader *)msg;

    SIZE_T size = pk->MessageBody[0];
    const UINT8 * p = &pk->MessageBody[size + 1];
    p += 3;
    size = READ24(p);
    p += 3;
    if ( p + size > msg + len )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }
    if ( !ExtractX509PublicKey(p, size) )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }

    m_phase = ReceivingCertificateVerify;

    return TRUE;
}


BOOL CTls13::ParseCertificateVerify(const UINT8 * msg, SIZE_T len)
{
    if ( m_phase != ReceivingCertificateVerify )
    {
        SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return FALSE;
    }

    if ( len < sizeof(PacketHeader) + 4 )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }

    const UINT8 * p = ((const PacketHeader *)msg)->MessageBody;

    INT32 algo = READ16(p);
    p += 2;
    SIZE_T siglen = READ16(p);
    p += 2;
    const UINT8 * sig = p;

    if ( &sig[siglen] < &msg[len] )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }

    UINT8 hash[64 + 33 + 1 + HASH_SIZE];
    for ( INT32 i = 0; i < 64; i++ )
    {
        hash[i] = 0x20; // ' '
    }
    memcpy(hash + 64, "TLS 1.3, server CertificateVerify", 33 + 1); // including '\0'

    CSha256 sha = m_transHash;
    sha.Finish(hash + 64 + 33 + 1);

    BOOL match = FALSE;

    switch ( algo )
    {
        case 0x0804:    // rsa_pss_rsae_sha256
            if ( siglen == 256 && m_certAlgorithm == RSA )
            {
                UINT32 e = 0;
                for ( SIZE_T i = 0; i < m_certKeyLength2; i++ )
                {
                    e = (e << 8) | m_certPublicKey2[i];
                }

                CRsaKey2048Pub pub;
                if ( pub.LoadBytes(m_certPublicKey1, m_certKeyLength1, e) )
                {
                    match = RsaVerifyPSS_SHA256(pub, hash, sizeof(hash), sig);
                }
            }
            break;

        case 0x0403:    // ecdsa_secp256r1_sha256
            if ( m_certAlgorithm == ECDSA )
            {
                UINT8 buf[64];
                if ( ParsePublicKeyEcdsa(buf, sig, siglen ) )
                {
                    sha.Initialize();
                    sha.Update(hash, sizeof(hash));
                    sha.Finish(hash);
                    CEcdsa<EcCurve::P256>::CPublicKey pub;
                    pub.x.fromBytesBE(m_certPublicKey1, m_certKeyLength1);
                    pub.y.fromBytesBE(m_certPublicKey2, m_certKeyLength2);
                    match = CEcdsa<EcCurve::P256>::VerifyDigest(pub, hash, buf);
                }
            }
            break;

        case 0x0807:    // ed25519
            if ( siglen == 64 && m_certAlgorithm == ED25519 )
            {
                match = ed25519_verify(m_certPublicKey1, hash, sizeof(hash), sig);
            }
            break;
    }

    secure_zero(hash, sizeof(hash));

    if ( !match )
    {
        SendAlert(ALERT_FATAL, ALERT_DECRYPT_ERROR);
        return FALSE;
    }

    m_phase = ReceivingFinished;

    return TRUE;
}


BOOL CTls13::ParsePublicKeyEcdsa(UINT8 * out, const UINT8 * p, SIZE_T len)
{
    Asn1Node node;
    const UINT8 * end = p + len;

    secure_zero(out, 64);

    if ( !ReadAsn1Node(p, end, node) || node.tag != 0x30 )
    {
        return FALSE;
    }

    const UINT8 * next = node.next;
    if ( !ReadAsn1Node(node.value, node.next, node) || node.tag != 0x02 )
    {
        return FALSE;
    }
    while ( node.value[0] == 0x00 )
    {
        node.value++;
        node.length--;
    }
    if ( node.length > 0x20 )
    {
        return FALSE;
    }
    memcpy(out + (0x20 - node.length), node.value, node.length);

    if ( !ReadAsn1Node(node.next, next, node) || node.tag != 0x02 )
    {
        return FALSE;
    }
    while ( node.value[0] == 0x00 )
    {
        node.value++;
        node.length--;
    }
    if ( node.length > 0x20 )
    {
        return FALSE;
    }
    memcpy(out + 0x20 + (0x20 - node.length), node.value, node.length);

    return TRUE;
}


BOOL CTls13::ParseFinished(const UINT8 * msg, SIZE_T len)
{
    if ( m_phase != ReceivingFinished )
    {
        SendAlert(ALERT_FATAL, ALERT_UNEXPECTED_MESSAGE);
        return FALSE;
    }

    CHmac<CSha256> hmac;
    UINT8 hash[HASH_SIZE];

    CSha256 sha = m_transHash;
    sha.Finish(hash);
    hmac.Initialize(m_serverFinishedKey, sizeof(m_serverFinishedKey));
    hmac.Update(hash, sizeof(hash));
    hmac.Finish(hash);

    const UINT8 * p = ((const PacketHeader *)msg)->MessageBody;
    if ( &msg[len] < p + sizeof(hash) )
    {
        SendAlert(ALERT_FATAL, ALERT_ILLEGAL_PARAMETER);
        return FALSE;
    }
    if ( memcmp(p, hash, sizeof(hash)) != 0 )
    {
        SendAlert(ALERT_FATAL, ALERT_DECRYPT_ERROR);
        return FALSE;
    }

    m_phase = SendingFinished;

    return TRUE;
}


BOOL CTls13::EncryptPacket(UINT8 * msg, SIZE_T len)
{
    UINT8 vec[sizeof(m_clientIV)];

    memcpy(vec, m_clientIV, sizeof(vec));
    for ( INT32 i = 0; i < 8; i++ )
    {
        vec[11 - i] ^= (m_sendSequence >> (i * 8));
    }
    m_sendSequence++;

#if USE_CHACHA20POLY1305
    CChacha20Poly1305 chacha;

    chacha.Initialize(m_clientKey, vec);
    chacha.UpdateAad(msg, sizeof(RecordHeader));
    msg += sizeof(RecordHeader);
    len -= sizeof(RecordHeader);
    chacha.Encrypt(m_buf, msg, len);
    memcpy(msg, m_buf, len);
    chacha.Finish(&msg[len]);
#else
    CAesGcm aes;

    aes.SetKeys(m_clientKey, sizeof(m_clientKey));
    aes.Init(vec, sizeof(vec), msg, sizeof(RecordHeader));
    msg += sizeof(RecordHeader);
    len -= sizeof(RecordHeader);
    aes.Encrypt(m_buf, msg, len);
    aes.Finalize();
    memcpy(msg, m_buf, len);
    aes.GetTag(&msg[len]);
#endif

    return TRUE;
}


BOOL CTls13::DecryptPacket(UINT8 * msg, SIZE_T len)
{
    UINT8 vec[sizeof(m_serverIV)];

    memcpy(vec, m_serverIV, sizeof(vec));
    for ( INT32 i = 0; i < 8; i++ )
    {
        vec[11 - i] ^= (m_receiveSequence >> (i * 8));
    }
    m_receiveSequence++;

#if USE_CHACHA20POLY1305
    CChacha20Poly1305 chacha;

    chacha.Initialize(m_serverKey, vec);
    chacha.UpdateAad(msg, sizeof(RecordHeader));
    msg += sizeof(RecordHeader);
    len -= sizeof(RecordHeader) + TAG_SIZE;
    BOOL ret = chacha.VerifyAndDecrypt(m_buf, msg, len, &msg[len]);
    memcpy(msg, m_buf, len);

    return ret;
#else
    CAesGcm aes;

    aes.SetKeys(m_serverKey, sizeof(m_serverKey));
    aes.Init(vec, sizeof(vec), msg, sizeof(RecordHeader));
    msg += sizeof(RecordHeader);
    len -= sizeof(RecordHeader) + TAG_SIZE;
    aes.SetTag(&msg[len]);
    aes.Decrypt(m_buf, msg, len);
    aes.Finalize();
    memcpy(msg, m_buf, len);

    return aes.CheckTag();
#endif
}


VOID CTls13::PrepareEncryption()
{
    switch ( m_keyExchange )
    {
        case Secp256r1:
            CEcdh<EcCurve::P256>::GetSharedSecret(m_sharedSecret, m_privateKey, m_serverPublicKey);
            break;
        case X25519:
            CX25519::GetSharedSecret(m_sharedSecret, m_privateKey, m_serverPublicKey);
            break;
    }

    UINT8 info[2 + 1 + 20 + 1 + HASH_SIZE];   // length + label_len + label + context_len + context
    UINT8 handshake[HASH_SIZE];
    UINT8 chs[HASH_SIZE];
    UINT8 shs[HASH_SIZE];
    UINT8 trans_hash[HASH_SIZE];
    UINT8 zero_hash[HASH_SIZE];
    UINT8 zero[HASH_SIZE] = { 0 };
    SIZE_T len;

    CSha256 sha = m_transHash;

    sha.Finish(trans_hash);
    sha.Initialize();
    sha.Finish(zero_hash);

    CHkdf<CSha256> hkdf;

    hkdf.Initialize(zero, sizeof(zero), zero, sizeof(zero));
    len = MakeLabel(info, sizeof(handshake), "derived", zero_hash, sizeof(zero_hash));
    hkdf.DeriveKey(info, len, handshake, sizeof(handshake));

    hkdf.Initialize(handshake, sizeof(handshake), m_sharedSecret, PV_KEYSIZE);
    len = MakeLabel(info, sizeof(chs), "c hs traffic", trans_hash, sizeof(trans_hash));
    hkdf.DeriveKey(info, len, chs, sizeof(chs));
    len = MakeLabel(info, sizeof(shs), "s hs traffic", trans_hash, sizeof(trans_hash));
    hkdf.DeriveKey(info, len, shs, sizeof(shs));
    len = MakeLabel(info, sizeof(m_derivedSecret), "derived", zero_hash, sizeof(zero_hash));
    hkdf.DeriveKey(info, len, m_derivedSecret, sizeof(m_derivedSecret));

    hkdf.SetPrk(chs);
    len = MakeLabel(info, sizeof(m_clientKey), "key");
    hkdf.DeriveKey(info, len, m_clientKey, sizeof(m_clientKey));
    len = MakeLabel(info, sizeof(m_clientIV), "iv");
    hkdf.DeriveKey(info, len, m_clientIV, sizeof(m_clientIV));
    len = MakeLabel(info, sizeof(m_clientFinishedKey), "finished");
    hkdf.DeriveKey(info, len, m_clientFinishedKey, sizeof(m_clientFinishedKey));

    hkdf.SetPrk(shs);
    len = MakeLabel(info, sizeof(m_serverKey), "key");
    hkdf.DeriveKey(info, len, m_serverKey, sizeof(m_serverKey));
    len = MakeLabel(info, sizeof(m_serverIV), "iv");
    hkdf.DeriveKey(info, len, m_serverIV, sizeof(m_serverIV));
    len = MakeLabel(info, sizeof(m_serverFinishedKey), "finished");
    hkdf.DeriveKey(info, len, m_serverFinishedKey, sizeof(m_serverFinishedKey));

    m_sendSequence = 0;
    m_receiveSequence = 0;
}


VOID CTls13::PrepareEncryption2(const UINT8 * trans_hash)
{
    UINT8 info[2 + 1 + 20 + 1 + HASH_SIZE];   // length + label_len + label + context_len + context
    UINT8 cap[HASH_SIZE];
    UINT8 sap[HASH_SIZE];
    UINT8 zero[HASH_SIZE] = { 0 };
    SIZE_T len;

    CHkdf<CSha256> hkdf;

    hkdf.Initialize(m_derivedSecret, sizeof(m_derivedSecret), zero, sizeof(zero));
    len = MakeLabel(info, sizeof(cap), "c ap traffic", trans_hash, HASH_SIZE);
    hkdf.DeriveKey(info, len, cap, sizeof(cap));
    len = MakeLabel(info, sizeof(sap), "s ap traffic", trans_hash, HASH_SIZE);
    hkdf.DeriveKey(info, len, sap, sizeof(sap));

    hkdf.SetPrk(cap);
    len = MakeLabel(info, sizeof(m_clientKey), "key");
    hkdf.DeriveKey(info, len, m_clientKey, sizeof(m_clientKey));
    len = MakeLabel(info, sizeof(m_clientIV), "iv");
    hkdf.DeriveKey(info, len, m_clientIV, sizeof(m_clientIV));

    hkdf.SetPrk(sap);
    len = MakeLabel(info, sizeof(m_serverKey), "key");
    hkdf.DeriveKey(info, len, m_serverKey, sizeof(m_serverKey));
    len = MakeLabel(info, sizeof(m_serverIV), "iv");
    hkdf.DeriveKey(info, len, m_serverIV, sizeof(m_serverIV));

    m_sendSequence = 0;
    m_receiveSequence = 0;
}

SIZE_T CTls13::MakeLabel(UINT8 * out, SIZE_T outlen, const CHAR8 * label, const UINT8 * context, SIZE_T ctxlen)
{
    static const CHAR8 tag[] = "tls13 ";
    SIZE_T i;

    WRITE16(out, outlen);

    for ( i = 0; i < sizeof(tag) - 1; i++ )
    {
        out[i + 3] = tag[i];
    }

    while ( *label )
    {
        out[i + 3] = *label;
        i++;
        label++;
    }
    out[2] = (UINT8)i;

    i += 3;
    SIZE_T j = i++;
    while ( ctxlen > 0 )
    {
        out[i] = *context;
        i++;
        context++;
        ctxlen--;
    }
    out[j] = (UINT8)(i - j - 1);

    return i;
}


BOOL CTls13::ReadAsn1Node(const UINT8 * p, const UINT8 * end, Asn1Node & node)
{
    if ( p + 2 >= end )
    {
        return FALSE;
    }

    node.tag = *p++;

    SIZE_T len = *p++;

    if ( (len & 0x80) != 0 )
    {
        SIZE_T bytes = len & 0x7f;

        if ( p + bytes > end )
        {
            return FALSE;
        }

        len = 0;
        while ( bytes-- )
        {
            len = (len << 8) | *p++;
        }
    }
    node.length = len;

    if ( p + node.length > end )
    {
        return FALSE;
    }

    node.value = p;
    node.next = p + node.length;

    return TRUE;
}

BOOL CTls13::ExtractX509PublicKey(const UINT8 * in, SIZE_T inlen)
{
    static const UINT8 RSA_OID[] =
    {
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
    };
    static const UINT8 ECDSA_OID[] =
    {
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
    };
    static const UINT8 ED25519_OID[] =
    {
        0x2b, 0x65, 0x70
    };

    const UINT8 * start = in;
    const UINT8 * end = in + inlen;
    Asn1Node node[5];
    struct {
        const UINT8 * start;
        const UINT8 * end;
        INT32 position;
    } stack[4];
    INT32 depth = 0;
    INT32 childpos = 0;
    BOOL foundkey = FALSE;
    BOOL foundalgo = FALSE;

    for ( ; ; )
    {
        if ( !ReadAsn1Node(start, end, node[depth]) )
        {
            if ( depth <= 1 )   // not found
            {
                return FALSE;
            }
            depth--;
            start = stack[depth].start;
            end = stack[depth].end;
            childpos = stack[depth].position;
            continue;
        }
        childpos++;
        switch ( node[depth].tag )
        {
            case 0x03:  // BIT STRING = pickup public key
                if ( depth == 3 && childpos == 2 &&
                     stack[1].position == 1 && stack[0].position == 1 )
                {
                    if ( foundalgo )
                    {
                        switch ( m_certAlgorithm )
                        {
                            case RSA:
                                if ( ExtractRsaPublicKey(node[depth].value, node[depth].length) )
                                {
                                    return TRUE;
                                }
                                break;

                            case ECDSA:
                                if ( ExtractEcdsaPublicKey(node[depth].value, node[depth].length) )
                                {
                                    return TRUE;
                                }
                                break;

                            case ED25519:
                                if ( ExtractEd25519PublicKey(node[depth].value, node[depth].length) )
                                {
                                    return TRUE;
                                }
                                break;

                            default:
                                break;
                        }
                    }
                    return FALSE;
                }
                start = node[depth].next;
                break;

            case 0x06:  // OID = signature algorithm
                if ( depth == 4 && childpos == 1 &&
                     (stack[2].position == 6 || stack[2].position == 7) &&
                     stack[1].position == 1 && stack[0].position == 1 )
                {
                    foundalgo = TRUE;
                    if ( memcmp(node[depth].value, RSA_OID, node[depth].length) == 0 )
                    {
                        m_certAlgorithm = RSA;
                    }
                    else if ( memcmp(node[depth].value, ECDSA_OID, node[depth].length) == 0 )
                    {
                        m_certAlgorithm = ECDSA;
                    }
                    else if ( memcmp(node[depth].value, ED25519_OID, node[depth].length) == 0 )
                    {
                        m_certAlgorithm = ED25519;
                    }
                    else
                    {
                        foundalgo = FALSE;
                    }
                    if ( foundkey && foundalgo )
                    {
                        return TRUE;
                    }
                }
                start = node[depth].next;
                break;

            case 0x30:
                if ( depth < 5 )
                {
                    stack[depth].start = node[depth].next;
                    stack[depth].end = end;
                    stack[depth].position = childpos;
                    start = node[depth].value;
                    end = node[depth].next;
                    childpos = 0;
                    depth++;
                }
                else
                {
                    start = node[depth].next;
                }
                break;

            default:
                start = node[depth].next;
                break;
        }
    }
}

BOOL CTls13::ExtractRsaPublicKey(const UINT8 * p, SIZE_T len)
{
    Asn1Node node1;
    Asn1Node node2;

    p++; len--; // skip first one byte

    if ( !ReadAsn1Node(p, p + len, node1) ||
         node1.tag != 0x30 ||
         node1.next > p + len )
    {
        return FALSE;
    }
    if ( !ReadAsn1Node(node1.value, node1.next, node2) ||
         node2.tag != 0x02 ||
         node2.next > node1.next )
    {
        return FALSE;
    }
    if ( node2.value[0] == 0x00 )
    {
        node2.value++;
        node2.length--;
    }
    if ( node2.length > sizeof(m_certPublicKey1) )
    {
        return FALSE;
    }
    memcpy(m_certPublicKey1, node2.value, node2.length);
    m_certKeyLength1 = node2.length;

    if ( !ReadAsn1Node(node2.next, node1.next, node2) ||
         node2.tag != 0x02 ||
         node2.next > node1.next )
    {
        return FALSE;
    }
    if ( node2.value[0] == 0x00 )
    {
        node2.value++;
        node2.length--;
    }
    if ( node2.length > sizeof(m_certPublicKey2) )
    {
        return FALSE;
    }

    memcpy(m_certPublicKey2, node2.value, node2.length);
    m_certKeyLength2 = node2.length;

    return TRUE;
}

BOOL CTls13::ExtractEcdsaPublicKey(const UINT8 * p, SIZE_T len)
{
    p++; len--; // skip first one byte

    if ( *p != 0x04 )
    {
        return FALSE;
    }
    p++; len--; // skip 0x04
    len /= 2;
    if ( len > MIN(sizeof(m_certPublicKey1), sizeof(m_certPublicKey2)) )
    {
        return FALSE;
    }
    memcpy(m_certPublicKey1, p, len);
    m_certKeyLength1 = len;
    memcpy(m_certPublicKey2, p + len, len);
    m_certKeyLength2 = len;

    return TRUE;
}

BOOL CTls13::ExtractEd25519PublicKey(const UINT8 * p, SIZE_T len)
{
    p++; len--; // skip first one byte

    if ( len > sizeof(m_certPublicKey1) )
    {
        return FALSE;
    }
    memcpy(m_certPublicKey1, p, len);
    m_certKeyLength1 = len;

    return TRUE;
}


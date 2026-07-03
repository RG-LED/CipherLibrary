/* ========================================================================== */
/**
 * @file    asconhashbase.h
 * @brief   Ascon hash (V1.2) base class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCONHASHBASE_H_)
#define _ASCONHASHBASE_H_

#include "asconbebase.h"
#include "secure.h"

class CAsconHashBase : public CAsconBeBase
{
public:
    ~CAsconHashBase() { secure_zero(m_buf, sizeof(m_buf)); }
    VOID Update(const UINT8 * data, SIZE_T len);

protected:
    VOID Initialize(UINT64 iv);
    VOID Finish();
    VOID Absorb(const UINT8 data[8]);

    SIZE_T m_buflen;
    UINT8 m_buf[8];
    INT32 m_round;
};

#endif // #if !defined(_ASCONHASHBASE_H_)


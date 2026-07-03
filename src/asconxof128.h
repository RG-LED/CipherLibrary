/* ========================================================================== */
/**
 * @file    asconxof128.h
 * @brief   Ascon-XOF128 hash class
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_ASCONXOF128_H_)
#define _ASCONXOF128_H_

#include "asconlebase.h"
#include "secure.h"

class CAsconXof128 : public CAsconLeBase
{
public:
    ~CAsconXof128()
    {
        secure_zero(m_buf, sizeof(m_buf));
    }
    VOID Initialize();
    VOID Update(const UINT8 * data, SIZE_T len);
    VOID Finish();
    VOID Squeeze(UINT8 * out, SIZE_T len);

protected:
    VOID Absorb(const UINT8 data[8]);

    SIZE_T m_buflen;
    UINT8 m_buf[8];
};

#endif // #if !defined(_ASCONXOF128_H_)


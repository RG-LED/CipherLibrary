/* ========================================================================== */
/**
 * @file    RandomGenerator.h
 * @brief   Random generation routine (for Windows)
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_RANDOMGENERATOR_H_)
#define _RANDOMGENERATOR_H_

#include "BasicDefs.h"

class CRandomGenerator
{
public:
    CRandomGenerator();

    VOID Fill(UINT8 * p, SIZE_T len);
    UINT8 GetByte();
    UINT16 GetWord();
    UINT32 GetDword();

private:
};

#endif  /* _RANDOMGENERATOR_H_ */


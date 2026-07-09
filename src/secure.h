/* ========================================================================== */
/**
 * @file    secure.cpp
 * @brief   functions for secure coding
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_SECURE_H_)
#define _SECURE_H_

#include "BasicDefs.h"

VOID secure_zero(VOID * p, SIZE_T n);
BOOL secure_equal(const VOID * p, const VOID * q, SIZE_T n);
VOID secure_random(VOID * p, SIZE_T n);

#endif // _SECURE_H_


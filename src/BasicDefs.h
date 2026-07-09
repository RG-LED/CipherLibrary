/* ========================================================================== */
/**
 * @file    BasicDefs.h
 * @brief   Basic data type definitions and utility function declarations
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#if !defined(_BASICDEFS_H_)
#define _BASICDEFS_H_

/* You have to define data types below properly for your environment in this file
    INT8    INT16   INT32   INT64
    UINT8   UINT16  UINT32  UINT64
    REAL32  REAL64
    CHAR8   BOOL    SIZE_T
    VOID

   You also need macros below to be defined properly
    TRUE    FALSE
    NULL
    MAX     MIN
 */

#include <basetsd.h>

#define CHAR8   char
#define BOOL    bool
#define VOID            void

#if !defined(FALSE)
#define FALSE           (BOOL)0
#define TRUE            (BOOL)1
#endif /* !FALSE */

#ifndef NULL
#ifdef __cplusplus
#define NULL            0
#else
#define NULL            ((void *)0)
#endif
#endif

#ifndef MAX
#define MAX(a, b)   ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b)   ((a) < (b) ? (a) : (b))
#endif

/* Following function must be declared properly for your environment
    memcpy()
 */

#include "memory.h"

#endif /* _BASICDEFS_H_ */


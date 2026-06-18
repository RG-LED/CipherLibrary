/* ========================================================================== */
/**
 * @file    RandomGenerator.cpp
 * @brief   Random generation routine (for Windows)
 */
/* ========================================================================== */
/* written by R&G-LED                                                         */
/* ========================================================================== */

#include "windows.h"
#include "mutex"
#include "time.h"
#include "RandomGenerator.h"
#include "Chacha20.h"
#include "sha256.h"

static CChacha20 randomizer;
static std::mutex * random_mutex = NULL;

CRandomGenerator::CRandomGenerator()
{
    GUID guid;
    CoCreateGuid(&guid);

    UINT32 seed[3];
    seed[0] = (UINT32)time(NULL);
    DWORD pid = GetCurrentProcessId();
    seed[1] = ((pid >> 16) | (pid << 16)) ^ GetTickCount();
    seed[2] = (UINT32)(UINT64)this;

    UINT8 seed32[32];
    UINT8 nonce12[12];

    CSha256 sha;
    sha.Initialize();
    sha.Update((UINT8 *)&guid, sizeof(guid));
    sha.Update((UINT8 *)&seed, sizeof(seed));
    sha.Finish(seed32);

    memcpy(nonce12, seed, sizeof(nonce12));

    if ( random_mutex == NULL )
    {
        random_mutex = new std::mutex;
    }

    std::lock_guard<std::mutex> lock(*random_mutex);
    randomizer.Initialize(seed32, nonce12);
}

VOID CRandomGenerator::Fill(UINT8 * p, SIZE_T len)
{
    std::lock_guard<std::mutex> lock(*random_mutex);
    randomizer.Read(p, len);
}

UINT8 CRandomGenerator::GetByte()
{
    std::lock_guard<std::mutex> lock(*random_mutex);
    return randomizer.Read8();
}

UINT16 CRandomGenerator::GetWord()
{
    std::lock_guard<std::mutex> lock(*random_mutex);
    return randomizer.Read16();
}

UINT32 CRandomGenerator::GetDword()
{
    std::lock_guard<std::mutex> lock(*random_mutex);
    return randomizer.Read32();
}


#pragma once

#include <Windows.h>

typedef struct _USTRING
{
    unsigned long Length;
    unsigned long MaximumLength;
    unsigned char* Buffer;
} USTRING, * PUSTRING;

typedef struct _RC4_CONTEXT
{
    unsigned char state[256];
    unsigned char x, y;
} RC4_CONTEXT;

void SystemFunction032(PUSTRING data, PUSTRING key);

void* RemovePadding(
    _In_    unsigned char* Data,
    _In_    int                 DataSize,
    _In_    int                 RealSize
);
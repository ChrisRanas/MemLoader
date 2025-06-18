#include <Windows.h>

#include "Encrypt.h"

void rc4_init(RC4_CONTEXT* a4i, const unsigned char* key, unsigned int keyLen)
{
    unsigned int keyIndex = 0, stateIndex = 0;
    unsigned int i, a;

    a4i->x = a4i->y = 0;

    for (i = 0; i < 256; i++)
        a4i->state[i] = i;

    for (i = 0; i < 256; i++)
    {
        a = a4i->state[i];
        stateIndex += key[keyIndex] + a;
        stateIndex &= 0xff;
        a4i->state[i] = a4i->state[stateIndex];
        a4i->state[stateIndex] = a;
        if (++keyIndex >= keyLen)
            keyIndex = 0;
    }
}

void rc4_crypt(RC4_CONTEXT* a4i, unsigned char* inoutString, unsigned int length)
{
    unsigned char* const s = a4i->state;
    unsigned int x = a4i->x;
    unsigned int y = a4i->y;
    unsigned int a, b;

    while (length--)
    {
        x = (x + 1) & 0xff;
        a = s[x];
        y = (y + a) & 0xff;
        b = s[y];
        s[x] = b;
        s[y] = a;
        *inoutString++ ^= s[(a + b) & 0xff];
    }

    a4i->x = x;
    a4i->y = y;
}

void* RemovePadding(
    _In_  unsigned char* Data,
    _In_  int DataSize,
    _In_  int RealSize
)
{
    if (!Data || DataSize <= 0 || RealSize <= 0 || RealSize > DataSize)
        return nullptr;

    unsigned char* OutputBuff = (unsigned char*)malloc(RealSize);
    if (!OutputBuff)
        return nullptr;

    int copied = 0;
    int remaining = RealSize;

    for (int i = 0; i < DataSize && remaining > 0; i += 2048)
    {
        int toCopy = min(1024, remaining);
        memcpy(OutputBuff + copied, Data + i, toCopy);
        copied += toCopy;
        remaining -= toCopy;
    }

    memcpy(Data, OutputBuff, RealSize);

    return reinterpret_cast<void*>(OutputBuff);
}


void SystemFunction032(PUSTRING data, PUSTRING key)
{
    RC4_CONTEXT a4i;

    rc4_init(&a4i, key->Buffer, key->Length);
    rc4_crypt(&a4i, data->Buffer, data->Length);

    return;
}

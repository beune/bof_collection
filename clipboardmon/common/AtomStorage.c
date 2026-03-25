#include <windows.h>
#include "struct.h"

#define ATOM_SUFFIX L"clipboardmon"

VOID SetMemAddr(pSharedData address)
{
    ATOM foundAtom;
    WCHAR atomName[] = L"\x01" ATOM_SUFFIX;

    // Loop over 64 bits in x64 size_t
    for (int count = 0; count < sizeof(size_t) * 8; count++)
    {
        // Check whether bit is set in address
        if ((size_t)address & ((size_t)1 << count))
        {
            // Bit is set. If atom doesn't already exist, add it.
            if (!FindAtomW(atomName))
                AddAtomW(atomName);
        }
        else
        {
            // Bit is unset. Call DeleteAtom until atom is removed.
            while ((foundAtom = FindAtomW(atomName)) != 0)
                DeleteAtom(foundAtom);
        }

        // Increment first byte in atomName to create atom name for next loop
        atomName[0] += 1;
    }

    return;
}

pSharedData GetMemAddr()
{
    size_t address = 0;
    WCHAR atomName[] = L"\x01" ATOM_SUFFIX;

    // Loop over 64 bits in x64 size_t
    for (int count = 0; count < sizeof(size_t) * 8; count++)
    {
        // Check whether Atom exists. If yes, bit = 1, if no bit = 0
        size_t bit = FindAtomW(atomName) == 0 ? 0 : 1;

        // Shift bit left <count> places then use OR assignment to set address
        address |= (bit << count);

        // Increment first byte in atomName to create atom name for next loop
        atomName[0] += 1;
    }

    return (pSharedData)address;
}

#include <windows.h>
#include "../beacon.h"

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    // Store Beacon start and end address in shared struct
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    VirtualQuery(BeaconPrintf, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

    PVOID BeaconAllocationBase = mbi.AllocationBase;
    PVOID BeaconAllocationEnd;

    while (BeaconAllocationBase == mbi.AllocationBase) {
        // Mark allocation end by adding region size to base address
        BeaconAllocationEnd = mbi.BaseAddress + mbi.RegionSize;

        // Call VirtualQuery on address one byte past allocation end to enum next region
        RtlSecureZeroMemory(&mbi, sizeof(MEMORY_BASIC_INFORMATION));
        VirtualQuery(BeaconAllocationEnd + 1, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Beacon start address: 0x%llx\nBeacon end address:   0x%llx\nBeacon size:          0x%llx", BeaconAllocationBase, BeaconAllocationEnd, BeaconAllocationEnd - BeaconAllocationBase);
}

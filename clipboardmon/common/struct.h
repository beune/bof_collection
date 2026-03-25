#pragma once
#include <windows.h>

typedef struct _SharedData {
    LPVOID pStardust;
    int stardust_len;
    HANDLE hStardustThread;
    HANDLE hEvent;
    PVOID pBeaconPrintf;
} SharedData, *pSharedData;

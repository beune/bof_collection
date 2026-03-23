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
    const char* key = NULL;
    BeaconDataParse(&parser, Buffer, Length);
    hostname = BeaconDataExtract(&parser, NULL);
    key = BeaconDataExtract(&parser, NULL);

    char remoteName[256];

    // Prepend "\\" for UNC format
    snprintf(remoteName, sizeof(remoteName), "\\\\%s", hostname);

    HKEY hRemoteBase = NULL;

    // Connect to remote registry
    LONG result = RegConnectRegistryA(
        remoteName,
        HKEY_LOCAL_MACHINE,
        &hRemoteBase
    );

    if (result != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegConnectRegistry failed: 0x%08x. Are you a domain-joined user and is RRP running?", result);
    }

    // Sanity check: ensure that we are not able to open the key
    HKEY hkResult;
    if (RegOpenKeyA(hRemoteBase, key, &hkResult) == ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Write access already available for %s. Exiting early...", key);
        RegCloseKey(hRemoteBase);
        RegCloseKey(hkResult);
        return;
    }

    // Delete key (must be relative to the opened hive)
    result = RegDeleteKeyA(
        hRemoteBase,
        key
    );

    if (result == ERROR_FILE_NOT_FOUND) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s does NOT exist on %s.", key, hostname);
    } else if (result == ERROR_ACCESS_DENIED){
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s exists on %s.", key, hostname);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown error code: 0x%08x.", result);
    }

    // Cleanup
    RegCloseKey(hRemoteBase);
};

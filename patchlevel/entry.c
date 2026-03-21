#include <windows.h>
#include "../beacon.h"

VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    datap parser = {0};
    const char * hostname = NULL;
    BeaconDataParse(&parser, Buffer, Length);
    hostname = BeaconDataExtract(&parser, NULL);

    HKEY hRemoteHKLM = NULL;
    HKEY hKey = NULL;

    char productName[256] = {0};
    char currentBuild[64] = {0};
    DWORD ubr = 0;

    DWORD type;
    DWORD size;

    // Connect to remote registry
    if (RegConnectRegistryA(hostname, HKEY_LOCAL_MACHINE, &hRemoteHKLM) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to connect to remote registry. Are you an authenticated user and is the machine reachable?");
        return;
    }

    // Open key
    if (RegOpenKeyExA(
            hRemoteHKLM,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            0,
            KEY_READ,
            &hKey) != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open registry key");
        RegCloseKey(hRemoteHKLM);
        return;
    }

    // Read ProductName
    size = sizeof(productName);
    if (RegQueryValueExA(hKey, "ProductName", NULL, &type, (LPBYTE)productName, &size) != ERROR_SUCCESS) {
        strcpy(productName, "Unknown");
    }

    // Read CurrentBuild
    size = sizeof(currentBuild);
    if (RegQueryValueExA(hKey, "CurrentBuild", NULL, &type, (LPBYTE)currentBuild, &size) != ERROR_SUCCESS) {
        strcpy(currentBuild, "Unknown");
    }

    // Read UBR (DWORD)
    size = sizeof(ubr);
    if (RegQueryValueExA(hKey, "UBR", NULL, &type, (LPBYTE)&ubr, &size) != ERROR_SUCCESS) {
        ubr = 0;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] %s has patch level %s.%lu (%s)",
           hostname,
           currentBuild,
           ubr,
           productName);

    RegCloseKey(hKey);
    RegCloseKey(hRemoteHKLM);
};

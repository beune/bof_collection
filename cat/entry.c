#include <windows.h>
#include "../beacon.h"

#define MAX_FILE_SIZE (128 * 1024)

static int is_safe_ascii(unsigned char b)
{
    return (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r';
}

/* Sanitize a UTF-8 buffer in place; returns the resulting length.
 * Valid multi-byte sequences are preserved, invalid bytes and control
 * characters (except \t \n \r) are replaced with '?'.
 */
static int sanitize_utf8(char *buf, int len)
{
    int in = 0, out = 0;
    while (in < len) {
        unsigned char b = (unsigned char)buf[in];
        if (b == 0x00) {
            in++;
            continue;
        }
        if (b < 0x80) {
            buf[out++] = is_safe_ascii(b) ? (char)b : '?';
            in++;
            continue;
        }

        int seq = 0;
        if ((b & 0xE0) == 0xC0) seq = 2;
        else if ((b & 0xF0) == 0xE0) seq = 3;
        else if ((b & 0xF8) == 0xF0) seq = 4;

        if (seq == 0 || in + seq > len) {
            buf[out++] = '?';
            in++;
            continue;
        }

        int valid = 1;
        for (int i = 1; i < seq; i++) {
            if (((unsigned char)buf[in + i] & 0xC0) != 0x80) { valid = 0; break; }
        }

        if (!valid) {
            buf[out++] = '?';
            in++;
            continue;
        }

        for (int i = 0; i < seq; i++) buf[out++] = buf[in + i];
        in += seq;
    }
    return out;
}

VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    datap parser = {0};
    const char *filename = NULL;
    BeaconDataParse(&parser, Buffer, Length);
    filename = BeaconDataExtract(&parser, NULL);

    if (!filename || !*filename) {
        BeaconPrintf(CALLBACK_ERROR, "No filename provided.");
        return;
    }

    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open '%s': %lu", filename, GetLastError());
        return;
    }

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hFile, &sz)) {
        BeaconPrintf(CALLBACK_ERROR, "GetFileSizeEx failed: %lu", GetLastError());
        CloseHandle(hFile);
        return;
    }

    if (sz.QuadPart > MAX_FILE_SIZE) {
        BeaconPrintf(CALLBACK_ERROR,
                     "File too large: %lld bytes (limit is %d bytes).",
                     sz.QuadPart, MAX_FILE_SIZE);
        CloseHandle(hFile);
        return;
    }

    DWORD file_size = (DWORD)sz.QuadPart;

    if (file_size == 0) {
        BeaconPrintf(CALLBACK_OUTPUT_UTF8, "[+] %s (empty file)", filename);
        CloseHandle(hFile);
        return;
    }

    char *raw = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, file_size);
    if (!raw) {
        BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed.");
        CloseHandle(hFile);
        return;
    }

    DWORD total = 0;
    while (total < file_size) {
        DWORD got = 0;
        if (!ReadFile(hFile, raw + total, file_size - total, &got, NULL) || got == 0)
            break;
        total += got;
    }
    CloseHandle(hFile);

    if (total == 0) {
        BeaconPrintf(CALLBACK_ERROR, "ReadFile returned no data.");
        HeapFree(GetProcessHeap(), 0, raw);
        return;
    }

    unsigned char *ub = (unsigned char *)raw;
    int is_utf16_le = 0, is_utf16_be = 0;
    DWORD offset = 0;

    if (total >= 3 && ub[0] == 0xEF && ub[1] == 0xBB && ub[2] == 0xBF) {
        offset = 3;
    } else if (total >= 2 && ub[0] == 0xFF && ub[1] == 0xFE) {
        is_utf16_le = 1;
        offset = 2;
    } else if (total >= 2 && ub[0] == 0xFE && ub[1] == 0xFF) {
        is_utf16_be = 1;
        offset = 2;
    } else {
        /* No BOM. Sniff for UTF-16 by looking at NUL distribution
         * in a leading sample; ASCII-in-UTF16 will have many zero bytes. */
        DWORD sample = total < 512 ? total : 512;
        DWORD null_even = 0, null_odd = 0;
        for (DWORD i = 0; i < sample; i++) {
            if (ub[i] == 0) {
                if ((i & 1) == 0) null_even++;
                else null_odd++;
            }
        }
        if (null_odd > sample / 4 && null_even < 2) is_utf16_le = 1;
        else if (null_even > sample / 4 && null_odd < 2) is_utf16_be = 1;
    }

    char *utf8 = NULL;
    int utf8_len = 0;

    if (is_utf16_le || is_utf16_be) {
        DWORD wchar_bytes = total - offset;
        int wchar_count = (int)(wchar_bytes / 2);
        wchar_t *wbuf = (wchar_t *)(raw + offset);

        if (is_utf16_be) {
            unsigned char *p = (unsigned char *)wbuf;
            for (int i = 0; i < wchar_count; i++) {
                unsigned char t = p[2 * i];
                p[2 * i] = p[2 * i + 1];
                p[2 * i + 1] = t;
            }
        }

        int need = WideCharToMultiByte(CP_UTF8, 0, wbuf, wchar_count,
                                       NULL, 0, NULL, NULL);
        if (need <= 0) {
            BeaconPrintf(CALLBACK_ERROR, "UTF-16 to UTF-8 conversion failed: %lu",
                         GetLastError());
            HeapFree(GetProcessHeap(), 0, raw);
            return;
        }

        utf8 = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)need);
        if (!utf8) {
            BeaconPrintf(CALLBACK_ERROR, "HeapAlloc failed.");
            HeapFree(GetProcessHeap(), 0, raw);
            return;
        }

        WideCharToMultiByte(CP_UTF8, 0, wbuf, wchar_count, utf8, need, NULL, NULL);
        utf8_len = need;
        HeapFree(GetProcessHeap(), 0, raw);
        raw = NULL;
    } else {
        utf8 = raw + offset;
        utf8_len = (int)(total - offset);
    }

    utf8_len = sanitize_utf8(utf8, utf8_len);

    BeaconPrintf(CALLBACK_OUTPUT_UTF8, "[+] %s", filename);
    BeaconOutput(CALLBACK_OUTPUT_UTF8, utf8, utf8_len);

    if (raw) HeapFree(GetProcessHeap(), 0, raw);
    else HeapFree(GetProcessHeap(), 0, utf8);
}

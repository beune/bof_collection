#pragma once
#include "beacon.h"
#include <windows.h>

#ifndef bufsize
#define bufsize 8192
#endif

char *output __attribute__((section(".data"))) = 0;
WORD currentoutsize __attribute__((section(".data"))) = 0;

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
#define intFree(addr) HeapFree(GetProcessHeap(), 0, (addr))

void printoutput(BOOL done)
{
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    memset(output, 0, bufsize);
    if (done) {
        intFree(output);
        output = NULL;
    }
}

int bofstart(void)
{
    output = (char *)intAlloc(bufsize);
    currentoutsize = 0;
    return 1;
}

void internal_printf(const char *format, ...)
{
    int buffersize = 0;
    int transfersize = 0;
    char *curloc = NULL;
    char *intBuffer = NULL;
    va_list args;

    va_start(args, format);
    buffersize = vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (buffersize == -1)
        return;

    char *transferBuffer = (char *)intAlloc(bufsize);
    /* +1: vsnprintf needs room for the null; using only buffersize truncates the last char (\n) to \0 */
    intBuffer = (char *)intAlloc(buffersize + 1);
    va_start(args, format);
    vsnprintf(intBuffer, buffersize + 1, format, args);
    va_end(args);

    if (buffersize + currentoutsize < bufsize) {
        memcpy(output + currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    } else {
        curloc = intBuffer;
        while (buffersize > 0) {
            transfersize = bufsize - currentoutsize;
            if (buffersize < transfersize)
                transfersize = buffersize;
            memcpy(output + currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;
            if (currentoutsize == bufsize)
                printoutput(FALSE);
            memset(transferBuffer, 0, transfersize);
            curloc += transfersize;
            buffersize -= transfersize;
        }
    }
    intFree(intBuffer);
    intFree(transferBuffer);
}

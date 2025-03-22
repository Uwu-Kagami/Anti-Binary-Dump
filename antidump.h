#pragma once
#include <Windows.h>
#include <winternl.h>
#include <iostream>

#define XOR_KEY 0xAA

typedef struct _LDR_DATA_TABLE_ENTRY LDR_DATA_TABLE_ENTRY;
typedef struct _PEB {
    BYTE Reserved1[2];
    struct {
        PVOID Reserved2[2];
    } Ldr;
} PEB, *PPEB;

PPEB GetPeb() {
    return (PPEB)__readgsqword(0x60);
}

bool IsDebuggerPresentEx() {
    BOOL isDebuggerPresent = FALSE;
    __asm {
        call IsDebuggerPresent
        mov isDebuggerPresent, eax
    }
    return isDebuggerPresent != FALSE;
}

void AntiDumpingTools() {
    if (IsDebuggerPresentEx()) {
        MessageBoxA(NULL, "Debugger Detected! Exiting...", "Protection", MB_OK);
        ExitProcess(1);
    }
}

void ModifyImageSize() {
    const auto peb = GetPeb();
    const auto inLoadOrderModuleList = (PLIST_ENTRY)peb->Ldr.Reserved2[1];
    const auto tableEntry = CONTAINING_RECORD(inLoadOrderModuleList, LDR_DATA_TABLE_ENTRY, Reserved1[0]);
    PULONG pSizeOfImage = (PULONG)&tableEntry->Reserved3[1];
    *pSizeOfImage = (ULONG)((INT_PTR)tableEntry->DllBase + 0x100000);
}

void EncryptMemory(void* baseAddress, size_t size) {
    unsigned char* ptr = (unsigned char*)baseAddress;
    for (size_t i = 0; i < size; ++i) {
        ptr[i] ^= XOR_KEY;
    }
}

void AntiDumpAdvanced() {
    AntiDumpingTools();
    ModifyImageSize();
    const auto baseAddr = (void*)GetModuleHandle(NULL);
    const size_t size = 0x1000;
    EncryptMemory(baseAddr, size);
    EncryptMemory(baseAddr, size);
}

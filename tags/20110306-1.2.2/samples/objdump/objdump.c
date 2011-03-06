/*
 * Copyright 2010 sakamoto.gsyc.3s@gmail.com
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

/**
 * COFF OBJ file dump utility sample
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <stdio.h>

// {{{ _print_last_error()

static void
_print_last_error(DWORD err)
{
    LPTSTR lpMsgBuf;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
            | FORMAT_MESSAGE_FROM_SYSTEM 
            | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, err,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpMsgBuf, 0, NULL);
    fprintf(stderr, "%s\n", lpMsgBuf);
    LocalFree(lpMsgBuf);
}

// }}}
// {{{ _load_data()

LPVOID
_load_data(LPCTSTR lpFileName)
{
    HANDLE hFile;
    DWORD datalen;
    DWORD readlen;
    LPVOID membuf = NULL;
    hFile = CreateFile(
            lpFileName, 
            GENERIC_READ, 
            0,
            NULL, OPEN_EXISTING, 0, NULL);
    if (INVALID_HANDLE_VALUE == hFile) {
        _print_last_error(GetLastError());
        return NULL;
    }
    datalen = GetFileSize(hFile, NULL);
    if (INVALID_FILE_SIZE == datalen) {
        _print_last_error(GetLastError());
        return NULL;
    }
    membuf = (LPVOID)GlobalAlloc(GMEM_ZEROINIT, datalen);
    if (NULL == membuf) {
        _print_last_error(GetLastError());
        return NULL;
    }
    if (!ReadFile(hFile, membuf, datalen, &readlen, NULL)) {
        GlobalFree(membuf);
        _print_last_error(GetLastError());
        return NULL;
    }
    CloseHandle(hFile);
    return membuf;
}

// }}}
// {{{ enum_reloc_cb()

BOOL
enum_reloc_cb(
        PCHEAP2EL_COFF_OBJ coff,
        PIMAGE_SECTION_HEADER sect,
        PIMAGE_RELOCATION reloc,
        int order,
        LPVOID lpApplicationData
        )
{
    printf("0x%08X, 0x%08X, 0x%04X in [%s], \n", 
            reloc->VirtualAddress, 
            reloc->SymbolTableIndex, 
            reloc->Type, 
            sect->Name);

    return FALSE;
}

// }}}
// {{{ enum_sym_cb()

BOOL
enum_sym_cb(
        PCHEAP2EL_COFF_OBJ coff,
        PIMAGE_SYMBOL symbol,
        char *symname,
        PIMAGE_AUX_SYMBOL aux_head,
        int order,
        LPVOID lpApplicationData
        )
{
    printf("[%d]\t0x%08X\t%d\t0x%04X\t0x%02X\t0x%02X\t\"%s\"\n",
            order, symbol->Value, symbol->SectionNumber, 
            symbol->Type, symbol->StorageClass, symbol->NumberOfAuxSymbols,
            symname);
    return FALSE;
}

// }}}

int main(int argc, char *argv[])
{
    PCHEAP2EL_COFF_OBJ coff = NULL;
    LPVOID lpvBuffer = NULL;
    CHEAP2EL_ERROR_CODE err = 0;
    char *cmd = NULL;
    char *file = NULL;
    int result;
    PIMAGE_SECTION_HEADER head;
    int i;

    if (3 != argc) {
        fprintf(stderr, "usage: %s [sect|reloc|sym] foobar.obj", argv[0]);
        return 1;
    }

    cmd = argv[1];
    file = argv[2];

    lpvBuffer = _load_data(file);
    if (NULL == lpvBuffer) {
        fprintf(stderr, "_load_data(%s) failed\n", file);
        return 2;
    }

    coff = cheap2el_coff_obj_map_from_memory(lpvBuffer, &err);
    if (NULL == coff) {
        fprintf(stderr, "map failed, err = %d\n", err);
        return 3;
    }

    printf("==> FILE HEADER <==\n");
    printf("[Mach]\t[Section#]\t[TimeDate]\t[SymPtr]\t[Sym#]\n");
    printf("0x%04X\t0x%04X\t0x%08X\t0x%08X\t0x%08X\n",
            coff->fileHeader->Machine, 
            coff->fileHeader->NumberOfSections, 
            coff->fileHeader->TimeDateStamp, 
            coff->fileHeader->PointerToSymbolTable, 
            coff->fileHeader->NumberOfSymbols);
    printf("\n");

    if (!stricmp("sect", cmd)) {
        printf("==> SECTIONS <==\n");
        printf("[#]\t[Offset]\t[Size]\t[Offset(Reloc)]\t[Reloc#]\t[Character]\t[Name]\n");
        head = coff->sectionHeaders;
        for (i = 0; i < coff->fileHeader->NumberOfSections; i++, head++) {
            printf("%d\t0x%08X\t0x%08X\t0x%08X\t0x%04X\t0x%08X\t%s\n",
                    i, head->PointerToRawData, head->SizeOfRawData,
                    head->PointerToRelocations, head->NumberOfRelocations, 
                    head->Characteristics, head->Name);
        }
        printf("-----------------\n%d sections.\n", i);
    } else if (!stricmp("reloc", cmd)) {
        printf("==> RELOCATIONS <==\n");
        printf("[VirtualAddress]\t[Symbol#]\t[Type]\t[Section]\n");
        head = coff->sectionHeaders;
        for (i = 0; i < coff->fileHeader->NumberOfSections; i++, head++) {
            result = cheap2el_coff_obj_enumerate_relocations(coff, head, 
                    enum_reloc_cb, (LPVOID)NULL);
        }
        printf("-----------------\n%d relocations.\n", result);
    } else if (!stricmp("sym", cmd)) {
        printf("[#]\t[Value]\t[Sect#]\t[Type]\t[Storage]\t[Aux#]\t[Name]\n");
        result = cheap2el_coff_obj_enumerate_symbols(coff,
            enum_sym_cb, (LPVOID)NULL);
        printf("-----------------\n%d symbols.\n", result);
    } else {
        fprintf(stderr, "unknown command : %s, use 'sect' or 'reloc' or 'sym'\n", cmd);
    }

    GlobalFree(coff);
    GlobalFree(lpvBuffer);
    return 0;
}

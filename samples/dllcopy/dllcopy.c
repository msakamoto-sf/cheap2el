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
 * copy dll into another process
 *
 * $Id$
 */

#include "cheap2el.h"
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef struct _DLLCOPY_ARGS {
    DWORD dwDestProcId;
    LPVOID lpFileBuffer;
    DWORD dwSizeOfImage;
    DWORD dwSizeOfHeader;
    HANDLE hProcess;
    LPVOID lpVirtualPageRemote;
    LPVOID lpVirtualPageLocal;
    HANDLE hThread;
    DWORD dwThreadId;
} DLLCOPY_ARGS, *PDLLCOPY_ARGS;

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
// {{{ find_dest_exe()

DWORD
find_dest_exe()
{
    HANDLE hProcessSnap;
    HANDLE hProcess;
    HMODULE hModule;
    DWORD cbNeeded;
    PROCESSENTRY32 pe32;
    DWORD dwProcId = 0;
    char szProcName[MAX_PATH];

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap) {
        _print_last_error(GetLastError());
        fprintf(stderr, "CreateToolhelp32Snapshot() failed\n");
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        _print_last_error(GetLastError());
        fprintf(stderr, "Process32First() failed\n");
        return 0;
    }

    do {
        hProcess = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                pe32.th32ProcessID);
        if (NULL != hProcess) {
            if (EnumProcessModules(
                        hProcess, &hModule, sizeof(hModule), &cbNeeded)) {
                GetModuleBaseName(hProcess, hModule, szProcName, 
                        sizeof(szProcName) / sizeof(szProcName[0]));
                if (!strcmp(szProcName, "dest_exe.exe")) {
                    dwProcId = pe32.th32ProcessID;
                }
            }
            CloseHandle(hProcess);
        }
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return dwProcId;
}

// }}}
// {{{ _load_test_data()

LPVOID
_load_test_data(LPCTSTR lpFileName)
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
// {{{ prepare_local()

PCHEAP2EL_PE_IMAGE
prepare_local(PDLLCOPY_ARGS args)
{
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    CHEAP2EL_CALLBACK_RESOLVE_IMPORTS_ARG resolve_arg;

    args->lpVirtualPageLocal = VirtualAlloc(
            NULL,
            args->dwSizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
    if (NULL == args->lpVirtualPageLocal) {
        _print_last_error(GetLastError());
        return NULL;
    }
    printf("lpVirtualPageLocal = 0x%p\n", args->lpVirtualPageLocal);

    pe = cheap2el_map_to_memory(
            args->lpFileBuffer,
            args->lpVirtualPageLocal,
            args->dwSizeOfImage,
            &err);
    if (NULL == pe) {
        fprintf(stderr, "cheap2el_map_to_memory() failed, code = %d\n", err);
        return NULL;
    }

    // resolve iat and other relocations
    pe->dwPseudoImageBase = (DWORD)args->lpVirtualPageRemote;
    if (!cheap2el_pseudo_load_address_resolver(pe, &resolve_arg)) {
        _print_last_error(resolve_arg.dwLastError);
        fprintf(stderr, "cheap2el_pseudo_load_address_resolver() failed\n");
        return NULL;
    }
    // update ImageBase in optionalheader
    pe->ntHeaders->OptionalHeader.ImageBase = pe->dwPseudoImageBase;

    return pe;
}

// }}}

int main(int argc, char *argv[])
{
    DLLCOPY_ARGS args;
    PCHEAP2EL_PE_IMAGE pe = NULL;
    CHEAP2EL_ERROR_CODE err;
    SIZE_T szbuf;
    DWORD dwptr;

    // find "dest_exe.exe" and get its process id.
    args.dwDestProcId = find_dest_exe();
    if (0 == args.dwDestProcId) {
        fprintf(stderr, "dest_exe.exe process was not found.\n");
        return 1;
    }
    printf("dest_exe.exe was found, process id is 0x%08X\n", args.dwDestProcId);

    // load "src_dll.dll" and retrieve image memory size
    args.lpFileBuffer = _load_test_data("src_dll.dll");
    if (NULL == args.lpFileBuffer) {
        fprintf(stderr, "_load_test_data() failed\n");
        return 2;
    }
    cheap2el_get_sizeofimage_from_file(
            args.lpFileBuffer,
            &(args.dwSizeOfImage),
            &(args.dwSizeOfHeader),
            &err);

    // get process handle for "dest_exe.exe"
    args.hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE, args.dwDestProcId);
    if (NULL == args.hProcess) {
        fprintf(stderr, "OpenProcess() failed\n");
        return 3;
    }

    // Allocate virtual page in target process
    args.lpVirtualPageRemote = VirtualAllocEx(
            args.hProcess,
            0,
            args.dwSizeOfImage,
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE);
    if (NULL == args.lpVirtualPageRemote) {
        _print_last_error(GetLastError());
        fprintf(stderr, "VirtualAllocEx() failed\n");
        return 4;
    }
    printf("virtual page is allocated from 0x%p\n", args.lpVirtualPageRemote);
    // prepare dll images executable in local memory
    pe = prepare_local(&args);
    if (NULL == pe) {
        fprintf(stderr, "prepare_local() failed\n");
        return 5;
    }
    printf("image is ready for copy in local memory at 0x%p\n",
            args.lpVirtualPageLocal);

    printf(">>> HIT RETURN KEY : copy dll images to dest_exe.exe\n");
    getchar();

    // copy prepared dll images into another process
    if (!WriteProcessMemory(
                args.hProcess,
                args.lpVirtualPageRemote,
                args.lpVirtualPageLocal,
                args.dwSizeOfImage,
                &szbuf)) {
        _print_last_error(GetLastError());
        fprintf(stderr, "WriteProcessMemory() failed\n");
        return 6;
    }

    dwptr = cheap2el_get_export_rva_by_name(pe, "msgbox_thread");
    printf("'msgbox_thread' rva is 0x%08X\n", dwptr);
    dwptr += pe->dwPseudoImageBase;
    printf("\tfixed actual address is 0x%08X\n", dwptr);

    printf(">>> HIT RETURN KEY : kick thread function in copyied dll\n");
    getchar();

    args.hThread = CreateRemoteThread(
            args.hProcess,
            NULL, // LPSECURITY_ATTRIBUTES
            0, // SIZE_T dwStackSize (use system default)
            (LPTHREAD_START_ROUTINE)(dwptr),
            NULL, // LPVOID lpParameter
            0, // DWORD dwCreationFlags (use default flag)
            &(args.dwThreadId));
    if (NULL == args.hThread) {
        _print_last_error(GetLastError());
        fprintf(stderr, "CreateRemoteThread() failed\n");
        return 7;
    }
    printf("thread id = 0x%08X\n", args.dwThreadId);

    // free resources
    if (!VirtualFree(args.lpVirtualPageLocal, 0, MEM_RELEASE)) {
        _print_last_error(GetLastError());
        fprintf(stderr, "VirtualFree() failed\n");
    }
    /*
    if (!VirtualFreeEx(
                args.hProcess, args.lpVirtualPageRemote, 0, MEM_RELEASE)) {
        _print_last_error(GetLastError());
        fprintf(stderr, "VirtualFreeEx() failed\n");
    }
    */
    GlobalFree(pe);
    GlobalFree(args.lpFileBuffer);
    CloseHandle(args.hProcess);

    return 0;
}

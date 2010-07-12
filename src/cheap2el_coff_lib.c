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
 * cheap2el : COFF Library file functions
 *
 * $Id: cheap2el_coff_obj.c 33 2010-07-09 14:26:53Z sakamoto.gsyc.3s@gmail.com $
 */

#include "cheap2el.h"
#include <windows.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

// {{{ _cheap2el_coff_lib_adjust_amh_offset

static DWORD
_cheap2el_coff_lib_adjust_amh_offset(
        DWORD offset
        )
{
    // align to 2 byte border.
    if (offset % 2) {
        return offset + 1;
    } else {
        return offset;
    }
}

// }}}
// {{{ cheap2el_coff_lib_get_am_size()

int
cheap2el_coff_lib_get_am_size(
        PIMAGE_ARCHIVE_MEMBER_HEADER amh
        )
{
    BYTE szSize[11];
    ZeroMemory(szSize, sizeof(szSize));

    memcpy(szSize, amh->Size, sizeof(szSize) - 1);
    StrTrimA(szSize, CHEAP2EL_COFF_LIB_AM_PADDING);
    return StrToIntA(szSize);
}

// }}}
// {{{ cheap2el_coff_lib_get_longname_offset()

int
cheap2el_coff_lib_get_longname_offset(
        const BYTE *Name
        )
{
    BYTE szName[17];
    ZeroMemory(szName, sizeof(szName));

    if (CHEAP2EL_COFF_LIB_AM_SPCHAR != Name[0]) {
        return 0;
    }
    memcpy(szName, Name, sizeof(szName) - 1);
    StrTrimA(szName, CHEAP2EL_COFF_LIB_AM_SPSTR CHEAP2EL_COFF_LIB_AM_PADDING);
    return StrToIntA(szName);
}

// }}}
// {{{ cheap2el_coff_lib_map_from_memory()

PCHEAP2EL_COFF_LIB
cheap2el_coff_lib_map_from_memory(
        LPVOID lpvMemoryBuffer,
        CHEAP2EL_ERROR_CODE *err
        )
{
    PCHEAP2EL_COFF_LIB lib = NULL;
    PIMAGE_ARCHIVE_MEMBER_HEADER amh = NULL;
    char *signature = NULL;
    DWORD dwptr1, dwptr2;
    BYTE szSize[11];
    size_t size;

    DWORD dwptr = 0;
    BYTE szName[17];
    LPVOID lpvMember;

    if (NULL == lpvMemoryBuffer) {
        *err = CHEAP2EL_EC_LACK_OF_MEMORY_BUFFER;
        return NULL;
    }

    lib = GlobalAlloc(GMEM_ZEROINIT, sizeof(CHEAP2EL_COFF_LIB));
    if (NULL == lib) {
        *err = CHEAP2EL_EC_MEMORY_ALLOC;
        return NULL;
    }

    lib->dwBase = (DWORD)lpvMemoryBuffer;
    signature = (char*)lpvMemoryBuffer;
    if (strncmp(IMAGE_ARCHIVE_START, signature, IMAGE_ARCHIVE_START_SIZE)) {
        *err = CHEAP2EL_EC_NOT_LIB_SIGNATURE;
        return NULL;
    }

    // 1st linker member
    dwptr1 = lib->dwBase + IMAGE_ARCHIVE_START_SIZE;
    amh = (PIMAGE_ARCHIVE_MEMBER_HEADER)dwptr1;
    if (CHEAP2EL_COFF_LIB_AM_SPCHAR == amh->Name[0] &&
        CHEAP2EL_COFF_LIB_AM_PADDING_CHAR == amh->Name[1]) {
        lib->amh_linker1 = amh;
        dwptr1 += IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR;
        lib->am_linker1 = (LPVOID)dwptr1;
    } else {
        *err = CHEAP2EL_EC_NOT_VALID_COFF_LIB;
        return NULL;
    }

    // 2nd linker member
    size = cheap2el_coff_lib_get_am_size(amh);
    dwptr1 = _cheap2el_coff_lib_adjust_amh_offset(dwptr1 + size);
    amh = (PIMAGE_ARCHIVE_MEMBER_HEADER)dwptr1;
    if (CHEAP2EL_COFF_LIB_AM_SPCHAR == amh->Name[0] &&
        CHEAP2EL_COFF_LIB_AM_PADDING_CHAR == amh->Name[1]) {
        lib->amh_linker2 = amh;
        dwptr1 += IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR;
        lib->am_linker2 = (LPVOID)dwptr1;
    } else {
        *err = CHEAP2EL_EC_NOT_VALID_COFF_LIB;
        return NULL;
    }

    // longname member
    size = cheap2el_coff_lib_get_am_size(amh);
    dwptr1 = _cheap2el_coff_lib_adjust_amh_offset(dwptr1 + size);
    amh = (PIMAGE_ARCHIVE_MEMBER_HEADER)dwptr1;
    if (CHEAP2EL_COFF_LIB_AM_SPCHAR == amh->Name[0] &&
        CHEAP2EL_COFF_LIB_AM_SPCHAR == amh->Name[1] &&
        CHEAP2EL_COFF_LIB_AM_PADDING_CHAR == amh->Name[2]) {
        lib->amh_longname = amh;
        dwptr1 += IMAGE_SIZEOF_ARCHIVE_MEMBER_HDR;
        lib->am_longname = (LPVOID)dwptr1;
    } else {
        *err = CHEAP2EL_EC_NOT_VALID_COFF_LIB;
        return NULL;
    }

    // head of object file members
    size = cheap2el_coff_lib_get_am_size(amh);
    dwptr1 = _cheap2el_coff_lib_adjust_amh_offset(dwptr1 + size);
    amh = (PIMAGE_ARCHIVE_MEMBER_HEADER)dwptr1;
    lib->amh_objects = amh;

    return lib;
}

// }}}
// {{{ cheap2el_coff_lib_enumerate_members()

int
cheap2el_coff_lib_enumerate_members(
        PCHEAP2EL_COFF_LIB lib,
        CHEAP2EL_COFF_LIB_ENUM_MEMBER_CALLBACK cb,
        LPVOID lpApplicationData
        )
{
    int result = 0;
    PIMAGE_ARCHIVE_MEMBER_HEADER amh = NULL;
    DWORD dwptr = 0, dwptr2;
    BYTE szName[17];
    char *szLongName;
    DWORD *dwpNumMem = NULL;
    DWORD *dwpOffsetMem = NULL;
    LPVOID lpvLinker2Member;

    if (NULL == cb) {
        return 0;
    }

    //TODO replace following codes with newer analyzing function.

    // get number of object linker members
    dwptr = (DWORD)lib->am_linker2;
    lpvLinker2Member = (LPVOID)dwptr;
    dwpNumMem = (DWORD*)lpvLinker2Member;

    // get member offset array
    dwpOffsetMem = (DWORD*)(dwptr + sizeof(DWORD));

    for (result = 0; result < *dwpNumMem; result++, dwpOffsetMem++) {
        dwptr = lib->dwBase + *dwpOffsetMem;
        amh = (PIMAGE_ARCHIVE_MEMBER_HEADER)dwptr;
        ZeroMemory(szName, sizeof(szName));

        if (CHEAP2EL_COFF_LIB_AM_SPCHAR != amh->Name[0]) {
            memcpy(szName, amh->Name, sizeof(szName) - 1);
            StrTrimA(szName, 
                    CHEAP2EL_COFF_LIB_AM_SPSTR CHEAP2EL_COFF_LIB_AM_PADDING);
            szLongName = szName;
        } else {
            dwptr2 = (DWORD)lib->am_longname;
            dwptr2 += cheap2el_coff_lib_get_longname_offset(amh->Name);
            szLongName = (char*)dwptr2;
        }

        if (NULL != cb && 
                cb(lib, amh, szLongName, (LPVOID)dwptr,
                    cheap2el_coff_lib_get_am_size(amh),
                    result, lpApplicationData)) {
            result++;
            break;
        }
    }
    return result;
}

// }}}

/**
 * Local Variables:
 * mode: php
 * coding: iso-8859-1
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * indent-tabs-mode: nil
 * End:
 * vim: set expandtab tabstop=4 shiftwidth=4:
 */

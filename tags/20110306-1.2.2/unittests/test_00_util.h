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
 * cheap2el : unittests utility function header
 *
 * $Id$
 */

#ifndef TEST_00_UTIL_H
#define TEST_00_UTIL_H

#include <windows.h>
#include "cheap2el.h"


#ifdef __cplusplus
extern "C" {
#endif

void
_hexdump(
        DWORD addr, 
        int len
        );

void
_print_last_error(
        DWORD err
        );

LPVOID
_load_test_data(
        LPCTSTR lpFileName
        );

typedef struct _lam_arg {
    LPVOID lpFileBuffer;
    LPVOID lpMemoryBuffer;
} lam_arg, *plam_arg;

PCHEAP2EL_PE_IMAGE
_load_and_map_test_data(
        plam_arg arg, 
        LPCSTR lpFileName, 
        CHEAP2EL_ERROR_CODE *err
        );

typedef struct _lam_arg2 {
    LPVOID lpFileBuffer;
    LPVOID lpVirtualPage;
} lam_arg2, *plam_arg2;

PCHEAP2EL_PE_IMAGE
_load_and_map_test_data2(
        LPVOID addr, 
        plam_arg2 arg, 
        LPCSTR lpFileName, 
        CHEAP2EL_ERROR_CODE *err
        );

#ifdef __cplusplus
}
#endif
#endif  /* TEST_00_UTIL_H */

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
 * replace_impaddr : provide hook procedure and inject payload.dll
 *
 * $Id$
 */

#include <windows.h>
#include <stdio.h>

#pragma data_seg(".shared")
static DWORD dwTargetProcessId = 0;
#pragma data_seg()

void SetMyKeyboardProcTarget(DWORD dwPid)
{
    dwTargetProcessId = dwPid;
}

LRESULT CALLBACK MyKeyboardProc(int code, WPARAM wParam, LPARAM lParam)
{
    DWORD dwPid = GetCurrentProcessId();
    if (dwTargetProcessId == dwPid) {
        // dummy stub
    }
    return CallNextHookEx(NULL, code, wParam, lParam);
}

BOOL WINAPI DllMain(
        HINSTANCE hInst, DWORD dwReason, LPVOID lpvReserved)
{
    DWORD dwPid = GetCurrentProcessId();

    switch (dwReason) {
        case DLL_PROCESS_ATTACH:
            if (dwTargetProcessId == dwPid) {
                printf("hook.dll attached to 0x%08X\n", dwPid);

                // inject payload.dll to target process
                LoadLibrary("payload.dll");
            }
            break;
        case DLL_PROCESS_DETACH:
            if (dwTargetProcessId == dwPid) {
                printf("hook.dll detached from 0x%08X\n", dwPid);
            }
            break;
    }
    return TRUE;
}

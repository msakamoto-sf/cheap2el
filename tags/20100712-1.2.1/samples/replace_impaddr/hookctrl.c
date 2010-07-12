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
 * replace_impaddr : hook.dll hooking on/off controller
 *
 * $Id$
 */

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include "hookctrl_res.h"

LRESULT __declspec(dllimport) CALLBACK MyKeyboardProc(int, WPARAM, LPARAM);
void __declspec(dllimport) SetMyKeyboardProcTarget(DWORD);

HHOOK hHook;

// {{{ find_proc_id()

DWORD find_proc_id(const char *exe_filename)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD dwProcId = 0;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        return 0;
    }

    do {
        if (!strcmp(pe32.szExeFile, exe_filename)) {
            dwProcId = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return dwProcId;
}

// }}}
// {{{ DialogProc()

BOOL CALLBACK DialogProc(
        HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_HOOK_ON:
                    hHook = SetWindowsHookEx(
                            WH_KEYBOARD,
                            MyKeyboardProc,
                            GetModuleHandle("hook.dll"),
                            0);
                    if (NULL == hHook) {
                        MessageBox(hWnd, "failed.", "hook on", MB_OK);
                    } else {
                        MessageBox(hWnd, "success.", "hook on", MB_OK);
                    }
                    return TRUE;
                case ID_HOOK_OFF:
                    if (!UnhookWindowsHookEx(hHook)) {
                        MessageBox(hWnd, "failed.", "hook off", MB_OK);
                    } else {
                        MessageBox(hWnd, "success.", "hook off", MB_OK);
                    }
                    return TRUE;
                case IDCANCEL:
                    EndDialog(hWnd, wParam);
                    return TRUE;
            }
    }
    return FALSE;
}

// }}}

int main(int argc, char *argv[])
{
    HWND hWndDesktop = NULL;
    HINSTANCE hCurrentInst = NULL;
    UINT_PTR uDlgRet = 0;
    DWORD dwTargetPid = find_proc_id("target.exe");
    if (0 == dwTargetPid) {
        printf("target.exe does not exists.\n");
        return 1;
    }

    SetMyKeyboardProcTarget(dwTargetPid);

    hCurrentInst = GetModuleHandle(NULL);
    hWndDesktop = GetDesktopWindow();
    DialogBox(
            hCurrentInst, 
            MAKEINTRESOURCE(IDD_DIALOG1), 
            hWndDesktop, 
            (DLGPROC)DialogProc);
    return 0;
}

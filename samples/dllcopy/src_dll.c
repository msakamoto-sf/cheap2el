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
 * dllcopy : source dll
 *
 * $Id$
 */

#include <windows.h>

typedef int (WINAPI *PMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);

DWORD __declspec(dllexport) WINAPI msgbox_thread(LPVOID lpParam)
{
    char msg[] = "Hello, World! - [_]\n";
    int i = 0;
    PMessageBox MyMessageBox = NULL;

    HMODULE hModule = LoadLibraryA("user32.dll");
    MyMessageBox = (PMessageBox)GetProcAddress(hModule, "MessageBoxA");

    while (1) {
        for (i = 0; i < 26; i++) {
            msg[17] = (char)(i + 0x41);
            MyMessageBox(NULL, msg, "caption", MB_OK);
            Sleep(3000);
        }
    }

    return 0;
}

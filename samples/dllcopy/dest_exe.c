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
 * dllcopy : destination stub process
 *
 * $Id$
 */

#include <windows.h>
#include <string.h>

int WINAPI
MyWinMain(
        HINSTANCE hInst, 
        HINSTANCE hPrevInst, 
        LPSTR lpCmdLine, 
        int nCmdShow)
{
    char msg[] = "Hello, World! - [_]\n";
    DWORD dwbuf;
    int i = 0;

    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (INVALID_HANDLE_VALUE == hStdOut) {
        return 1;
    }

    while (1) {
        for (i = 0; i < 26; i++) {
            msg[17] = i + 0x41;
            if (!WriteConsole(hStdOut, msg, strlen(msg), &dwbuf, NULL)) {
                return 2;
            }
            Sleep(1000);
        }
    }

    return 0;
}

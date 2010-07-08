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
 * cheap2el : stub COFF Object file for cunit testing
 *
 * $Id$
 */
#include <windows.h>
#pragma comment(lib, "user32.lib")

int vari01 = 100;
int vari02;
static int vari03;

char msg[] = "Hello, World!\n";

extern vari01e;

extern int func01e(int a, int b);
int __declspec(dllimport) func01dlli(int a, int b);
int __declspec(dllexport) func01dlle(int a, int b) { return a + b + 1; }

int func01(int a, int b) {
	int c;
	int d;
	int e;
	c = a;
	d = b;
	e = func01e(c, d);
	return e;
}
int func02(int a, int b) { return a * b; }
static int func03(int a, int b) { return func01(a, b) + func02(a, b); }
void func04(void) {
	int a = func03(vari01, vari02);
	vari03 += vari01e;
	a = func01dlle(100, 200);
	MessageBox(NULL, msg, "bar", MB_OK);
}

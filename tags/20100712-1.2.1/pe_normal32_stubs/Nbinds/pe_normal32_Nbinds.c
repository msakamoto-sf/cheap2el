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
 * cheap2el : stub dll (N binds main dll) main
 *
 * $Id$
 */

__declspec(dllimport) int funcA0(int a, int b);
__declspec(dllimport) int funcB0(int a, int b);
__declspec(dllimport) int funcB1(int a, int b);
__declspec(dllimport) int funcC0(int a, int b);
__declspec(dllimport) int funcC1(int a, int b);
__declspec(dllimport) int funcC2(int a, int b);
__declspec(dllimport) int funcD0(int a, int b);
__declspec(dllimport) int funcD1(int a, int b);
__declspec(dllimport) int funcD2(int a, int b);
__declspec(dllimport) int funcD3(int a, int b);
__declspec(dllimport) int funcE0(int a, int b);

int __declspec(dllexport) myfunc(void)
{
	int a;
	a = funcA0(1, 2);
	a = funcB0(1, 2);
	a = funcB1(1, 2);
	a = funcC0(1, 2);
	a = funcC1(1, 2);
	a = funcC2(1, 2);
	a = funcD0(1, 2);
	a = funcD1(1, 2);
	a = funcD2(1, 2);
	a = funcD3(1, 2);
	a = funcE0(1, 2);
	return 1;
}

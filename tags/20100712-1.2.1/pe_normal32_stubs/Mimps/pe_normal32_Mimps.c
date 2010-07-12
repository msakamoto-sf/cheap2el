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
 * cheap2el : stub dll (M imports main dll) main
 *
 * $Id$
 */

__declspec(dllimport) int varsA;
__declspec(dllimport) int varsB;
__declspec(dllimport) int foo(int a, int b);
__declspec(dllimport) int bar(int a, int b);
__declspec(dllimport) int func1(int a, int b);
__declspec(dllimport) int func2(int a, int b);
__declspec(dllimport) int func3(int a, int b);
/* __declspec(dllimport) int func4(int a, int b); */
/* __declspec(dllimport) int func5(int a, int b); */
__declspec(dllimport) int funcX(int a, int b); /* func6 */
/* __declspec(dllimport) int funcY(int a, int b); */ /* func7 */

int __declspec(dllexport) myfunc(void)
{
	int a = foo(1, 2);
	int b = bar(1, 2);
	int c = func1(varsA, varsB);
	int d = func2(1, 2);
	int e = func3(1, 2);
	int f = funcX(1, 2);
	return 1;
}

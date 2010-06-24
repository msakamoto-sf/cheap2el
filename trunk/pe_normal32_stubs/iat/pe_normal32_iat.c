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
 * cheap2el : stub dll (iat main dll) main
 *
 * $Id$
 */

__declspec(dllimport) int varsA;
__declspec(dllimport) int varsB;
__declspec(dllimport) int funcA1(int a);
__declspec(dllimport) int funcA2(int a);
__declspec(dllimport) int funcB1(int a);
__declspec(dllimport) int funcB2(int a);

int __declspec(dllexport) func1(int a, int b)
{
	return funcA1(a) + funcA2(b) + varsA;
}
int __declspec(dllexport) func2(int a, int b)
{
	return funcB1(a) + funcB2(b) + varsB;
}

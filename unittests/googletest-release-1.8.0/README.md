# Google Test Local Build Binary

- https://github.com/google/googletest
- using 1.8.0 release tag : https://github.com/google/googletest/releases/tag/release-1.8.0
- LICENSE: BSD-3-Clause

how to build: (non multi thread build.)
1. download 1.8.0 zip and extract.
2. open `googletest/msvc/gtest.sln` by Visual Studio 2017 (-> update project setting).
3. re-targetting solution to latest Windows SDK.
4. do x86 Release build.

build env:
- Windows 10 Pro 64bit
- Visual Studio 2017
- solution tagetted to Windows SDK 10.0.16299.0

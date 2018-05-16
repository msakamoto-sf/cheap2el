# About

- This directory includes ".exe" and ".dll" stub projects (sources, Makefiles) for c-unit test datas.
- All ".exe" and ".dll" have already been compiled, and stored in [..\unittests\datafiles](../unittests/datafiles/) directory ("pe_normal32_" prefix).

```
Compiled Platform : Pentium4, Windows XP SP3 (Japanese)
SDK : Microsoft Visual C++ 2008 Express Edition SP1 - Japanese

Compiler & Linker versions :
> cl
Microsoft(R) 32-bit C/C++ Optimizing Compiler Version 15.00.30729.01 for 80x86
Copyright (C) Microsoft Corporation.  All rights reserved.
> link
Microsoft (R) Incremental Linker Version 9.00.30729.01
Copyright (C) Microsoft Corporation.  All rights reserved.
```

If you want to recompile stub projects on your own platform:
1. open "Visual Studio 20xx command prompt"
2. change directory to each stub project directory.
3. type "nmake -f Makefile.mk" and hit return key.

Thank you.

Copyright 2010 sakamoto.gsyc.3s@gmail.com
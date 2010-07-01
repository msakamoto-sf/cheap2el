HOW TO PLAY WITH "expdef" SAMPLE

//-----------------------------------------------------------------------------
// STEP 1 : Build "expdef.exe"
//-----------------------------------------------------------------------------

1-1. open your visual studio command prompt.
1-2. cd to each sample directory you want to build.
1-3. do "nmake -f Makefile.mk"

When all works fine, we obtain "expdef.exe".


//-----------------------------------------------------------------------------
// STEP 2 : Build "dll1.dll" and generate "dll2.def"
//-----------------------------------------------------------------------------

Next, generate module definition file (.def) using expdef for "dll1.dll".

2-1. do "nmake -f Makefile.mk dll2.def".

Why "dll2.def" ? Because, ".def" for dll1.dll will be reused to export and 
forwarding symbols for dll2.dll build.

At this time, "dlltest.exe" will shows:
---------------------------
> dlltest.exe
func1(2, 3) = 6
func2(2, 3) = 7
---------------------------

//-----------------------------------------------------------------------------
// STEP 3 : Modify "dll2.def"
//-----------------------------------------------------------------------------

It's time to hook "func1()" in dll1.dll to dll2.dll's func1().

Now, "dll2.def" is like below:
--------------------------- START
LIBRARY dll1.dll
EXPORTS
    func1 = dll1.func1
    func2 = dll1.func2
--------------------------- END

Edit "LIBRARY dll1.dll" to "LIBRARY dll2.dll" and delete " = dll1.func1".

After, "dll2.def" will be like below:
--------------------------- START
LIBRARY dll2.dll
EXPORTS
    func1
    func2 = dll1.func2
--------------------------- END

Using this .def file, "dll2.dll" export "func1()" in itself, and forward
 "func2" to "dll1.dll"'s original "func2()".

//-----------------------------------------------------------------------------
// STEP 4 : Build "dll2.dll"
//-----------------------------------------------------------------------------

4-1. do "nmake -f Makefile.mk dll2.dll"

All works fine, then we obtain "dll2.dll".

//-----------------------------------------------------------------------------
// STEP 5 : Replace "dll1.dll" to "dll2.dll" in "dlltest.exe"
//-----------------------------------------------------------------------------

5-1. Open your favorite binary editor, and load "dlltest.exe"
5-2. Find "dll1.dll" string, and replace it to "dll2.dll"
5-3. Save "dlltest.exe".

At this time, "dlltest.exe" will shows:
---------------------------
> dlltest.exe
func1(2, 3) = 7            : dll2.dll's func1() return 2 * 3 + 1
func2(2, 3) = 7
---------------------------

//-----------------------------------------------------------------------------
// STEP X : It's your turn ...
//-----------------------------------------------------------------------------

Basic steps are all described above.
Now, your turn has come.
Bridge and hook your favorite dll, and replace it (like kernel32.dll)!!! :P


Copyright 2010 sakamoto.gsyc.3s@gmail.com

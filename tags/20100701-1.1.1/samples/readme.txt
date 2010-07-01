This directory includes sample projects using cheap2el.


* How to build samples

a. open your visual studio command prompt.
b. cd to each sample directory you want to build.
c. do "nmake -f Makefile.mk"


* Samples brief summaries

1. "expdef"

This sample outputs export symbol names in module definition (.def) file 
format. It's usable to create bridge(hooking) dlls.
For more details, see expdef\readme.txt.

2. "dllres"

This sample shows :
- How to embed binary data into resource section (using RCDATA type).
- How to retrieve embedded binary data from resource section.
- How to use cheap2el's dll pseudo loading feature.

This sample embeds "payload.dll" into exe's resource section, 
get "payload.dll" data from resource, 
pseudo loads "payload.dll" data (make pe image exectable), 
and call dll function in payload.dll.

3. "dllcopy"

This sample shows a way of "dll injection" using cheap2el.
To play this sample, you have to open two command prompts.
1st, execute dest_exe.exe in one command prompt.
2nd, in another command prompt, execute dllcopy.exe.
Then what happens ?
"dllcopy.exe" injects "src_dll.dll" into "dest_exe.exe" memory, 
make "src_dll.dll" image executable in "dest_exe.exe" memory, 
and call "DllMain" in "src_dll.dll" using by CreateRemoteThread().

4. "replace_impaddr"

This sample shows TWO ways of "rewrite(hook) import address" using cheap2el.
"payload.dll" is key dll which practically rewrite import address 
 of "MessageBoxA" in all modules's IATs when dll is loaded.
You can confirm "payload.dll" behaviour by executing "payload_test.exe".

When you play this samples, you have to open two command prompts.
1st, execute target.exe in one command prompt.
2nd, execute "hookctrl.exe" or "remoteload.exe" in another command prompt.

Two ways of "rewrite(hook) import address" are:
 i) Use HOOK to load "payload.dll" in target process.
ii) Call "LoadLibrary("payload.dll")" directly by using CreateRemoteThread() 
    in target process.

 i): "hookctrl.exe" and "hook.dll" shows how to setup keyboard hook and 
load "payload.dll" into another process when keyboard hook is called.

ii): "remoteload.exe" shows how to call "LoadLibrary()" by 
CreateRemoteThread(), and load "payload.dll" into target process.

Copyright 2010 sakamoto.gsyc.3s@gmail.com

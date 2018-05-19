# sample projects using cheap2el

This directory includes sample projects using cheap2el.

## How to build samples

1. open your visual studio command prompt.
2. cd to here (or each sample directory you want to build).
3. do `nmake`

## Samples brief summaries

### 1. "expdef"

[This sample](./expdef/) outputs export symbol names in module definition (.def) file format.
It's usable to create bridge(hooking) dlls.
For more details, see [expdef\README.md](./expdef/).

### 2. "dllres"

[This sample](./dllres/) shows :
- How to embed binary data into resource section (using `RCDATA` type).
- How to retrieve embedded binary data from resource section.
- How to use cheap2el's dll pseudo loading feature.

This sample ...
1. embeds "payload.dll" into exe's resource section,
2. get "payload.dll" data from resource,
3. pseudo loads "payload.dll" data (make pe image exectable),
4. and call dll function in payload.dll.

### 3. "dllcopy"

[This sample](./dllcopy/) shows a way of "dll injection" using cheap2el.

To play this sample, you have to open two command prompts.
1. execute dest_exe.exe in one command prompt.
2. in another command prompt, execute dllcopy.exe.

Then what happens ?
1. "dllcopy.exe" injects "src_dll.dll" into "dest_exe.exe" memory, 
2. make "src_dll.dll" image executable in "dest_exe.exe" memory, 
3. and call "DllMain" in "src_dll.dll" using by CreateRemoteThread().

NOTE: "dllcopy" samples don't work on Windows 7 (without Service Pack).
Please update to Windows 7 "SP1".

### 4. "replace_impaddr"

[This sample](./replace_impaddr/) shows TWO ways of "rewrite(hook) import address" using cheap2el.
"payload.dll" is key dll which practically rewrite import address of "MessageBoxA" in all modules's IATs when dll is loaded.
You can confirm "payload.dll" behaviour by executing "payload_test.exe".

When you play this samples, you have to open two command prompts.
1. execute target.exe in one command prompt.
2. execute "hookctrl.exe" or "remoteload.exe" in another command prompt.

Two ways of "rewrite(hook) import address" are:
1. Use SetWindowsHook to load "payload.dll" in target process.
   - "hookctrl.exe" and "hook.dll" shows how to setup keyboard hook and load "payload.dll" into another process when keyboard hook is called.
2. Call LoadLibrary("payload.dll") directly by using CreateRemoteThread() in target process.
   - "remoteload.exe" shows how to call LoadLibrary() by CreateRemoteThread(), and load "payload.dll" into target process.

For detailed component description, see [README.md](./replace/impaddr/).

### 5. "objdump"

[This sample](./objdump/) shows usage of COFF Object functions in cheap2el.
"objdump" dumps sections, relocations and symbols in COFF Object file.

### 6. "libdump"

[This sample](./libdump/) shows usage of COFF LIB functions in cheap2el.
"libdump" dumps file names ans symbols in COFF LIB file.

Copyright 2010 sakamoto.gsyc.3s@gmail.com

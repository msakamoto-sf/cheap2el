# About "replace_impaddr" source code structure

file dependency:
- IAT Replacer (Replace "MessageBoxA" to hooked function.)
  - payload.c (-> .dll) : enumerate module images in loaded process, then replace "MessageBoxA" to self-contained "MyMessageBoxA".
  - stubfwd.c, .def (-> .dll) : exports func1() and func2(), func2 is forwarded to "MessageBoxA".
  - payload_test.c (-> .exe) : payload.dll tester. LoadLibrary("payload.dll") then call stubfwd.func1(), stubfwd.func2().
- SetWindowsHookEx() Hook
  - hook.c (-> .dll) : exports custom WH_KEYBOARD hook function, and load payload.dll.
  - hookctrl.c (-> .exe) : setup WH_KEYBOARD hook to call hook.dll in target.exe -> target.exe receives WH_KEYBOARD event, then load hook.dll, then load payload.dll.
  - (a little complicated. read source code carefully.)
- CreateRemoteThread() then LoadLibrary() invoker
  - remoteload.c (-> .exe) : find "target.exe", c



## Basic Components

- target.c (.exe)
  - victim process (injectee)
  - implicitly linked to stubfwd.dll
- stubfwd.c, stubfwd.def (-> .dll)
  - exports func1() and func2(), func2 is forwarded to original user32.MessageBoxA()
- payload.c, payload.def (-> .dll)
  - enumerate module images in loaded process, then replace "MessageBoxA" to self-contained "MyMessageBoxA".
- payload_test.c (-> .exe)
  - payload.dll tester.
  - LoadLibrary("payload.dll") then call stubfwd.func1(), stubfwd.func2().
 
## Two ways of import address hooking

"SetWindowsHookEx()" injector:
- hook.c, hook.def (-> .dll)
  - exports custom WH_KEYBOARD hook function.
  - load payload.dll when attached to process (= dll loaded) in DllMain()
- hookctrl.c, hookctrl.rc, hookctrl_res.h (-> .exe)
  - setup WH_KEYBOARD hook to call hook.dll in target.exe
  - (-> target.exe receives WH_KEYBOARD event, then load hook.dll, then load payload.dll.)
  - SetWindowsHookEx() demo.

LoadLibrary() + CreateRemoteThread() injector:
- remoteload.c (-> .exe)
  - loads payload.dll into another process (= target.exe) by LoadLibrary() + CreateRemoteThread()


Copyright 2011 sakamoto.gsyc.3s@gmail.com
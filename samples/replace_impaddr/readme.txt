About "replace_impaddr" source code structure

* Basic Components

target.c :
 victim process (injectee)

stubfwd.c, stubfwd.def :
 exports "func2()" forwarding to original "MessageBoxA()"

payload.c, payload.def :
 replaces import addresses ("MessageBoxA()" => "MyMessageBoxA()")

payload_test.c : 
 test stub for payload.dll

* Two ways of import address hooking

** "SetWindowsHookEx()" injector

hook.c, hook.def : 
 provides hook procedure and inject payload.dll

hookctrl.c, hookctrl.rc, hookctrl_res.h : 
 controlls hook.dll hooking on/off

** "LoadLibrary()" + "CreateRemoteThread()" injector

remoteload.c : 
 loads payload.dll into another process


Copyright 2011 sakamoto.gsyc.3s@gmail.com
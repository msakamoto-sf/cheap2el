# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# replace_impaddr
# $Id$
#

!include <..\..\common.mk>
!include <..\common.mk>

all:remoteload.exe hookctrl.exe

remoteload.exe:remoteload.c payload_test.exe
	$(CC) $(CFLAGS) remoteload.c

hookctrl.exe:hookctrl.c hookctrl.res hook.dll
	$(CC) $(CFLAGS) hookctrl.c hookctrl.res psapi.lib user32.lib hook.lib

hookctrl.res:hookctrl.rc

hook.dll:hook.c hook.def payload_test.exe
	$(CC) $(CFLAGS) /LD hook.c user32.lib /link /def:hook.def /SECTION:.shared,rws

payload_test.exe:payload_test.c payload.dll target.exe
	$(CC) $(CFLAGS) payload_test.c user32.lib stubfwd.lib

payload.dll:payload.c
	$(CC) $(CFLAGS) /FAcs payload.c user32.lib $(CHEAP2EL_LIB) /LD

target.exe:target.c stubfwd.dll
	$(CC) $(CFLAGS) target.c user32.lib stubfwd.lib

stubfwd.dll:stubfwd.c stubfwd.def
	$(CC) $(CFLAGS) /LD stubfwd.c user32.lib /link /def:stubfwd.def

clean:
	del *.exe *.dll *.exp *.lib *.obj *.res


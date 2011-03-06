# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# dllcopy
# $Id$
#

PROJNAME=dllcopy
TARGET=$(PROJNAME).exe
SRCS=$(PROJNAME).c
OBJS=$(PROJNAME).obj


!include <..\..\common.mk>
!include <..\common.mk>

$(TARGET):$(OBJS) dest_exe.exe src_dll.dll
	$(CC) $(CFLAGS) $(OBJS) user32.lib psapi.lib $(CHEAP2EL_LIB)

dest_exe.exe:dest_exe.c
	$(CC) $(CFLAGS) /GS- dest_exe.c kernel32.lib \
		/link /subsystem:console /entry:MyWinMain

src_dll.dll:src_dll.c
	$(CC) $(CFLAGS) /LD src_dll.c kernel32.lib user32.lib /link /noentry /def:src_dll.def

clean:
	del *.exe *.dll *.exp *.lib *.obj *.res

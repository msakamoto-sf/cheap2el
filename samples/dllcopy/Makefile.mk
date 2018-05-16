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

# NOTE : "/entry" option suppress "/SUBSYSTEM" guessing and automatic crt lib links :(
# so we must add "/SUBSYSTEM" linker option EXPLICITLY, 
# and we must specify C Runtime Library file MANUALLY.
# (I selected static linkable libucrt.lib : see https://docs.microsoft.com/ja-jp/cpp/c-runtime-library/crt-library-features)
# ("/MT", "/MD", "/LD" option did not work.)
# other refs:
# https://docs.microsoft.com/ja-jp/cpp/build/reference/md-mt-ld-use-run-time-library
# https://docs.microsoft.com/ja-jp/cpp/build/reference/entry-entry-point-symbol
# https://docs.microsoft.com/ja-jp/cpp/build/reference/subsystem-specify-subsystem
dest_exe.exe:dest_exe.c
	$(CC) $(CFLAGS) /GS- dest_exe.c kernel32.lib libucrt.lib \
		/link /subsystem:console /entry:MyWinMain

src_dll.dll:src_dll.c
	$(CC) $(CFLAGS) /LD src_dll.c kernel32.lib user32.lib /link /noentry /def:src_dll.def

clean:
	del *.exe *.dll *.exp *.lib *.obj *.res

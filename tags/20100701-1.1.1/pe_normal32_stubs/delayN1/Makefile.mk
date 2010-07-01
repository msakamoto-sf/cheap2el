# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub dll (N-1 delay load) for cunit testing
# $Id$
#

PROJNAME=pe_normal32_delayN1
TARGET=$(PROJNAME).dll
SRCS=$(PROJNAME).c
OBJS=$(PROJNAME).obj

!include <..\..\common.mk>

$(TARGET):$(OBJS) $(PROJNAME)_stub1.dll $(PROJNAME)_stub2.dll
	$(CC) $(CFLAGS) /LD $(SRCS) \
		delayimp.lib \
		kernel32.lib \
		$(PROJNAME)_stub1.lib \
		$(PROJNAME)_stub2.lib \
		/link \
		/DELAYLOAD:$(PROJNAME)_stub1.dll \
		/DELAYLOAD:$(PROJNAME)_stub2.dll \
		/noentry

$(PROJNAME)_stub1.dll:build-force
	$(CC) $(CFLAGS) /LD $(PROJNAME)_stub1.c /link /noentry

$(PROJNAME)_stub2.dll:build-force
	$(CC) $(CFLAGS) /LD $(PROJNAME)_stub2.c /link /noentry

build-force:

clean:
	del *.dll *.exp *.lib *.obj

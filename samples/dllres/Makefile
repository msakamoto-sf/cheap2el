# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# RCDATA dll embedding and psudo load
# $Id$
#

PROJNAME=dllres
TARGET=$(PROJNAME).exe
SRCS=$(PROJNAME).c
OBJS=$(PROJNAME).obj


!include <..\..\common.mk>
!include <..\common.mk>

$(TARGET):$(OBJS) $(PROJNAME).res payload.dll
	$(CC) $(CFLAGS) $(SRCS) user32.lib $(PROJNAME).res $(CHEAP2EL_LIB)

dllres.res:dllres.rc payload.dll

payload.dll:payload.obj
	$(CC) $(CFLAGS) /LD payload.c user32.lib

clean:
	del *.exe *.dll *.exp *.lib *.obj *.res

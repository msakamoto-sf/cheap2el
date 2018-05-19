# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# print export forwarding list for ".def" file
# $Id$
#

PROJNAME=expdef
TARGET=$(PROJNAME).exe
OBJS=$(PROJNAME).obj

!include <..\..\common.mk>
!include <..\common.mk>

$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) /Fe$(TARGET) $(OBJS) $(CHEAP2EL_LIB) /link /NOLOGO

dll2.def:$(TARGET)
	$(CC) $(CFLAGS) /LD dll1.c
	$(CC) $(CFLAGS) dlltest.c dll1.lib
	$(TARGET) dll1.dll > dll2.def

dll2.dll:dll2.def
	$(CC) $(CFLAGS) /LD dll2.c dll1.lib /link /DEF:dll2.def

clean:
	del *.exe *.obj *.dll *.lib *.exp *.def

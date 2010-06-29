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
	$(CC) $(CFLAGS) /Fe$(TARGET) $(OBJS) $(CHEAP2EL_LIB) /link $(LFLAGS)

clean:
	del *.exe *.obj

# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# print export forwarding list for ".def" file
# $Id$
#

PROJNAME=expdef
TARGET=$(PROJNAME).exe
OBJS=$(PROJNAME).obj

!include <..\..\common.mk>

CFLAGS=$(CFLAGS) /I ..\..\header

$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) /Fe$(TARGET) $(OBJS) libcunit.lib ..\..\cheap2el.lib /link $(LFLAGS)

clean:
	del *.exe *.obj

# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# COFF OBJ file dump utility sample
# $Id$
#

PROJNAME=objdump
TARGET=$(PROJNAME).exe
SRCS=$(PROJNAME).c
OBJS=$(PROJNAME).obj


!include <..\..\common.mk>
!include <..\common.mk>

$(TARGET):$(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(CHEAP2EL_LIB)

clean:
	del *.exe *.obj

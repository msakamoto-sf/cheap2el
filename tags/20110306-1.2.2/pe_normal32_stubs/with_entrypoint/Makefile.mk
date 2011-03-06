# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub dll (with entry point) for cunit testing
# $Id$
#

PROJNAME=pe_normal32_with_entrypoint
TARGET=$(PROJNAME).dll
SRCS=$(PROJNAME).c
OBJS=$(PROJNAME).obj

!include <..\..\common.mk>

$(TARGET):$(OBJS) $(RESOURCES)
	$(CC) $(CFLAGS) /LD $(SRCS) \
		/link \
		/entry:MyDllMain \
		/def:$(PROJNAME).def \
		/nodefaultlib

$(OBJS):$(SRCS)

clean:
	del *.dll *.lib *.exp *.obj *.res

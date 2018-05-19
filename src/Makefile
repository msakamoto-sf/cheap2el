# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : library
# $Id$
#

PROJNAME=cheap2el

TARGET=..\$(PROJNAME).lib
OBJS=$(PROJNAME)_mapper.obj \
     $(PROJNAME)_enumerator.obj \
     $(PROJNAME)_callbacks.obj \
     $(PROJNAME)_version.obj \
     $(PROJNAME)_coff_obj.obj \
     $(PROJNAME)_coff_lib.obj

!include <..\common.mk>

CFLAGS=$(CFLAGS) /I ..\header

$(TARGET):$(OBJS)
	lib /nologo /out:$(TARGET) $(OBJS)

clean:
	del *.obj
	del $(TARGET)

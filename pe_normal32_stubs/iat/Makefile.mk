# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : stub dll (iat) for cunit testing
# $Id$
#

PROJNAME1=pe_normal32_iat
PROJNAME2=pe_normal32_iat_stub

!include <..\..\common.mk>

$(PROJNAME1).dll:$(PROJNAME1).obj $(PROJNAME2)A.dll $(PROJNAME2)B.dll
	$(CC) $(CFLAGS) /LD $(PROJNAME1).c \
		$(PROJNAME2)A.lib \
		$(PROJNAME2)B.lib \
		/link /noentry

$(PROJNAME2)A.dll:$(PROJNAME2)A.obj
	$(CC) $(CFLAGS) /LD $(PROJNAME2)A.c /link /def:$(PROJNAME2)A.def /noentry

$(PROJNAME2)B.dll:$(PROJNAME2)B.obj
	$(CC) $(CFLAGS) /LD $(PROJNAME2)B.c /link /def:$(PROJNAME2)B.def /noentry

$(PROJNAME1).obj:$(PROJNAME1).c

$(PROJNAME2)A.obj:$(PROJNAME2)A.c

$(PROJNAME2)B.obj:$(PROJNAME2)B.c

clean:
	del *.dll *.exp *.lib *.obj

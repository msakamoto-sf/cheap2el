# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : common option macros
# $Id$
#

!IF DEFINED(CUNIT_INCPATH) && DEFINED(CUNIT_LIBPATH)
CFLAGS=/I $(CUNIT_INCPATH) /Od /Ob0 /Gd /W4 /nologo
LFLAGS=/LIBPATH:$(CUNIT_LIBPATH) /NOLOGO
!ELSE
CFLAGS=/Od /Ob0 /Gd /W4 /nologo
LFLAGS=/NOLOGO
!ENDIF

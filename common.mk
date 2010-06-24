# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : common option macros
# $Id$
#

CUNIT_INCPATH=C:\in_vitro\c\lib.c-unit-1.1.1\c-unit
CUNIT_LIBPATH=C:\in_vitro\c\lib.c-unit-1.1.1
CFLAGS=/I $(CUNIT_INCPATH) /Od /Ob0 /Gd
LFLAGS=/LIBPATH:$(CUNIT_LIBPATH)

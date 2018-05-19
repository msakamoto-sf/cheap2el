# Copyright 2010 sakamoto.gsyc.3s@gmail.com
# cheap2el : root Makefile
# $Id$
#

MAKEOPTS=-nologo

cheap2el:force-builds
	cd src && $(MAKE) $(MAKEOPTS) && cd ..

test:force-builds
	cd src && $(MAKE) $(MAKEOPTS) && cd ..
	set PATH=%PATH%;.\\datafiles
	cd unittests && $(MAKE) $(MAKEOPTS) && main.exe && cd ..

samples:force-builds
	cd samples && $(MAKE) $(MAKEOPTS) && cd ..

clean:force-builds
	cd src && $(MAKE) $(MAKEOPTS) clean && cd ..
	cd unittests && $(MAKE) $(MAKEOPTS) clean && cd ..
	cd samples && $(MAKE) $(MAKEOPTS) clean && cd ..

force-builds:

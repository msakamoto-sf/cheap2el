# Copyright 2018 sakamoto.gsyc.3s@gmail.com
# cheap2el : library
#

MAKEOPTS=-nologo

all:
    cd expdef && $(MAKE) $(MAKEOPTS) && cd ..
    cd dllres && $(MAKE) $(MAKEOPTS) && cd ..
    cd dllcopy && $(MAKE) $(MAKEOPTS) && cd ..
    cd replace_impaddr && $(MAKE) $(MAKEOPTS) && cd ..
    cd objdump && $(MAKE) $(MAKEOPTS) && cd ..
    cd libdump && $(MAKE) $(MAKEOPTS) && cd ..

clean:
    cd expdef && $(MAKE) $(MAKEOPTS) clean && cd ..
    cd dllres && $(MAKE) $(MAKEOPTS) clean && cd ..
    cd dllcopy && $(MAKE) $(MAKEOPTS) clean && cd ..
    cd replace_impaddr && $(MAKE) $(MAKEOPTS) clean && cd ..
    cd objdump && $(MAKE) $(MAKEOPTS) clean && cd ..
    cd libdump && $(MAKE) $(MAKEOPTS) clean && cd ..


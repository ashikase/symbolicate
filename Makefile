build:
	make -f Makefile.x86_64
	make -f Makefile.armv6
	lipo -create obj/symbolicate obj/macosx/symbolicate -output symbolicate

clean:
	make -f Makefile.x86_64 clean
	make -f Makefile.armv6 clean

distclean:
	make -f Makefile.x86_64 distclean
	make -f Makefile.armv6 distclean

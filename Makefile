build:
	make -f Makefile.x86_64
	make -f Makefile.armv6
	lipo -create obj/symbolicate obj/macosx/symbolicate -output symbolicate
	mv symbolicate obj/symbolicate

clean:
	make -f Makefile.x86_64 clean
	make -f Makefile.armv6 clean

distclean:
	make -f Makefile.x86_64 distclean
	make -f Makefile.armv6 distclean

package: build
	make -f Makefile.armv6 package

install:
	make -f Makefile.armv6 install

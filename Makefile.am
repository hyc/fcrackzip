AUTOMAKE_OPTIONS = gnits

EXTRA_DIST = fcrackzip.txt fcrackzip.html fcrackzip.1 gencrack.pl zipcrack.c cpmask.c crackdef.c noradi.zip

# next line is for pgcc/egcs/gcc-2.8
#CFLAGS = -O6 -mpentiumpro -march=pentiumpro  -g -Wall
#CFLAGS = @CFLAGS@
#LDFLAGS = -g

man_MANS = fcrackzip.1
bin_PROGRAMS = fcrackzip zipinfo
noinst_HEADERS = getopt.h
fcrackzip_SOURCES = main.c crack.c crack.h crc32.h
fcrackzip_LDADD = @LIBOBJS@
zipinfo_SOURCES = zipinfo.c
zipinfo_LDADD = @LIBOBJS@

if HAVE_PERL
crack.c: crackdef.c

crackdef.c: zipcrack.c gencrack.pl
	@PERL@ gencrack.pl zipcrack.c
else
.PRECIOUS: crack.h crackd.c
endif

%.txt: %.1 Makefile.am
	nroff -mandoc <$< >$@

%.html: %.1 Makefile.am
	myman2html $< >$@

bin-strip: all
	strip fcrackzip

# everything below is maintainer-only!
copy-www: fcrackzip.txt fcrackzip.html fcrackzip bin-strip dist
	./myman2html fcrackzip.1 | tail +3 | tac | tail +7 | tac >/root/www/nh/fcrackzip.1.nh
	mv fcrackzip-$(VERSION).tar.gz /root/www/src/marc/data/
	cp fcrackzip /root/www/src/marc/data/fcrackzip-$(VERSION).linux86.bin
	gzip -9fv /root/www/src/marc/data/fcrackzip-$(VERSION).linux86.bin
	chmod 644 /root/www/src/marc/data/fcrackzip-$(VERSION).tar.gz
	chmod 644 /root/www/src/marc/data/fcrackzip-$(VERSION).linux86.bin.gz
	echo -n $(VERSION) >/root/www/nh/fcrackzip-ver.nh

test: all
	fcrackzip --benchmark



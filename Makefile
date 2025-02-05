

# Debug malloc support (http://dmalloc.com).  Comment out if you don't
# have dmalloc, but it is highly recommended.
#
#DMALLOC_CFLAGS = -I/usr/local/include -DDMALLOC=1
#DMALLOC_LIBS = -L/usr/local/lib -ldmalloc
#
# On Stanford machines, you need these paths for dmalloc:
#
#DMALLOC_CFLAGS = -I/afs/ir/class/cs144/dmalloc -DDMALLOC=1
#DMALLOC_LIBS = -L/afs/ir/class/cs144/dmalloc -ldmalloc

LIBRT = `test -f /usr/lib/librt.a && printf -- -lrt`

CC = gcc
#CFLAGS = -g -Wall -Werror $(DMALLOC_CFLAGS)
CFLAGS = -g -Wall $(DMALLOC_CFLAGS) #-fsanitize=address
LIBS = $(DMALLOC_LIBS)

all: reliable

.c.o:
	$(CC) $(CFLAGS) -c $<

rlib.o reliable.o: rlib.h

reliable: buffer.o reliable.o rlib.o
	$(CC) $(CFLAGS) -o $@ buffer.o reliable.o rlib.o $(LIBS) $(LIBRT)

.PHONY: tester reference
tester reference:
	cd tester-src && $(MAKE) Examples/reliable/$@
	cp tester-src/Examples/reliable/$@ .
	strip $@

TAR = reliable.tar.gz

SUBMIT = reliable/Makefile reliable/*.[ch] #reliable/README

.PHONY: submit
submit: clean
	ln -s . reliable
	tar -czf $(TAR) $(SUBMIT)
	rm -f reliable
	@echo '************************************************************'
	@echo '                                                            '
	@echo '  1. Please change the name $(TAR) to include netid         '
	@echo '      (e.g. reliable_netid.tar.gz)                          '
	@echo '                                                            '
	@echo '  2. Please upload the file to git repository               '
	@echo '      assigned to you                                       '
	@echo '                                                            '
	@echo '************************************************************'

.PHONY: dist
dist: clean tester reference
	cd tester-src && $(MAKE) clean
	./stripsol reliable.c > reliable.c-dist
	ln -s . reliable
	tar -czf $(TAR) \
		reliable/reliable.c-dist \
		reliable/Makefile reliable/rlib.[ch] \
		reliable/stripsol \
		reliable/tester reliable/reference
	rm -f reliable

.PHONY: clean
clean:
	@find . \( -name '*~' -o -name '*.o' -o -name '*.hi' \) \
		-print0 > .clean~
	@xargs -0 echo rm -f -- < .clean~
	@xargs -0 rm -f -- < .clean~
	rm -f reliable $(TAR)

.PHONY: clobber
clobber: clean
	cd tester-src && $(MAKE) clean
	rm -f tester reference reliable.c-dist

CC = gcc
VERSION = 1.1.2
CFLAGS = -g -O2
LIBS = -lcrypt -lcrypto -lssl -lpam -lz 
INSTALL=/usr/bin/install -c
prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/sbin
sysconfdir=${prefix}/etc
FLAGS=$(CFLAGS) -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_LIBZ=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DUSE_LINUX_CAPABILITIES=1 -D_LARGEFILE64_SOURCE=1 -D_FILE_OFFSET_BITS=64 -DHAVE_LIBPAM=1 -DHAVE_LIBSSL=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCRYPT=1 -DHAVE_SHADOW_H=1 
OBJ=Authenticate.o MimeType.o DavProps.o Settings.o common.o server.o directory_listing.o ChrootHelper.o ID3.o upload.o proxy.o libUseful-2.0/libUseful-2.0.a

all: $(OBJ)
	@cd libUseful-2.0; $(MAKE)
	gcc $(FLAGS) -o alaya $(LIBS) $(OBJ)  main.c

libUseful-2.0/libUseful-2.0.a: 
	@cd libUseful-2.0; $(MAKE)

Authenticate.o: Authenticate.c Authenticate.h
	gcc $(FLAGS) -c Authenticate.c

MimeType.o: MimeType.c MimeType.h
	gcc $(FLAGS) -c MimeType.c 

ChrootHelper.o: ChrootHelper.c ChrootHelper.h
	gcc $(FLAGS) -c ChrootHelper.c 

DavProps.o: DavProps.c DavProps.h
	gcc $(FLAGS) -c DavProps.c 

Settings.o: Settings.c Settings.h
	gcc $(FLAGS) -c Settings.c 

common.o: common.c common.h
	gcc $(FLAGS) -c common.c 

server.o: server.c server.h
	gcc $(FLAGS) -c server.c 

directory_listing.o: directory_listing.c directory_listing.h
	gcc $(FLAGS) -c directory_listing.c 

ID3.o: ID3.c ID3.h
	gcc $(FLAGS) -c ID3.c 

upload.o: upload.c upload.h
	gcc $(FLAGS) -c upload.c

proxy.o: proxy.c proxy.h
	gcc $(FLAGS) -c proxy.c


clean:
	rm -f *.o alaya */*.o */*.so */*.a


install:
	$(INSTALL) -d $(DESTDIR)$(bindir)
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)
	$(INSTALL) alaya $(DESTDIR)$(bindir)
	$(INSTALL) alaya.conf $(DESTDIR)$(sysconfdir)

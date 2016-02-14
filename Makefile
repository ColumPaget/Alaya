CC = gcc
CFLAGS = -g -O2
LIBS = -lcrypt -lcrypto -lssl -lpam -lz  #-lUseful-2.3
INSTALL=/usr/bin/install -c
prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/sbin
sysconfdir=${prefix}/etc
FLAGS=$(CFLAGS) -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_LIBZ=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DUSE_XATTR=1 -DUSE_LINUX_CAPABILITIES=1 -DHAVE_LIBPAM=1 -DHAVE_LIBSSL=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCRYPT=1 -DHAVE_SHADOW_H=1 
OBJ=Authenticate.o MimeType.o DavProps.o Settings.o common.o server.o FileProperties.o directory_listing.o FileDetailsPage.o VPath.o ChrootHelper.o Events.o ID3.o upload.o proxy.o websocket.o libUseful-2.3/libUseful-2.3.a 
EXE=alaya

all: $(OBJ)
	gcc $(FLAGS) -o $(EXE) $(OBJ) main.c $(LIBS) 

libUseful-2.3/libUseful-2.3.a: 
	@cd libUseful-2.3; $(MAKE)

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

VPath.o: VPath.c VPath.h
	gcc $(FLAGS) -c VPath.c 

Events.o: Events.c Events.h
	gcc $(FLAGS) -c Events.c 

directory_listing.o: directory_listing.c directory_listing.h
	gcc $(FLAGS) -c directory_listing.c 

FileDetailsPage.o: FileDetailsPage.c FileDetailsPage.h
	gcc $(FLAGS) -c FileDetailsPage.c 

FileProperties.o: FileProperties.c FileProperties.h
	gcc $(FLAGS) -c FileProperties.c 

ID3.o: ID3.c ID3.h
	gcc $(FLAGS) -c ID3.c 

upload.o: upload.c upload.h
	gcc $(FLAGS) -c upload.c

proxy.o: proxy.c proxy.h
	gcc $(FLAGS) -c proxy.c

websocket.o: websocket.c websocket.h
	gcc $(FLAGS) -c websocket.c


clean:
	rm -f *.o */*.o */*.so */*.a $(EXE)

distclean:
	-rm -f *.o */*.o */*.a */*.so $(EXE)
	-rm config.log config.status */config.log */config.status Makefile */Makefile
	-rm -r autom4te.cache */autom4te.cache


install:
	$(INSTALL) -d $(DESTDIR)$(bindir)
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)
	$(INSTALL) $(EXE) $(DESTDIR)$(bindir)
	$(INSTALL) alaya.conf $(DESTDIR)$(sysconfdir)

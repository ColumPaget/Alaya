CC = gcc
CFLAGS = -g -O2
CPPFLAGS = 
LIBS =  -lcrypt -lcrypto -lssl -lpam -lcap -lc -lc -lz  libUseful/libUseful.a
INSTALL=/bin/install -c
prefix=/usr/local
exec_prefix=${prefix}
bindir=${exec_prefix}/sbin
sysconfdir=${prefix}/etc
FLAGS=$(CFLAGS) $(CPPFLAGS) -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -D_FILE_OFFSET_BITS=64 -DHAVE_LIBZ=1 -DHAVE_LIBC=1 -DHAVE_LIBC=1 -DHAVE_LIBCAP=1 -DUSE_LINUX_CAPABILITIES=1 -DHAVE_LIBPAM=1 -DHAVE_LIBSSL=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBCRYPT=1 -DHAVE_SHADOW_H=1 
OBJ=auth_access_token.o Authenticate.o auth_client_certificate.o auth_alaya_native.o auth_unix.o auth_pam.o MimeType.o DavProps.o Settings.o common.o server.o cgi.o FileProperties.o tar.o directory_listing.o FileDetailsPage.o VPath.o ChrootHelper.o UserAdminScreen.o Events.o ID3.o upload.o proxy.o websocket.o icecast.o xssi.o libUseful/libUseful.a
EXE=alaya

all: $(OBJ)
	$(CC) $(FLAGS) -o $(EXE) $(OBJ) main.c $(LIBS) 

libUseful/libUseful.a: 
	@cd libUseful; $(MAKE)

auth_access_token.o: auth_access_token.c auth_access_token.h
	$(CC) $(FLAGS) -c auth_access_token.c

Authenticate.o: Authenticate.c Authenticate.h
	$(CC) $(FLAGS) -c Authenticate.c

auth_client_certificate.o: auth_client_certificate.c auth_client_certificate.h
	$(CC) $(FLAGS) -c auth_client_certificate.c

auth_alaya_native.o: auth_alaya_native.c auth_alaya_native.h
	$(CC) $(FLAGS) -c auth_alaya_native.c

auth_unix.o: auth_unix.c auth_unix.h
	$(CC) $(FLAGS) -c auth_unix.c

auth_pam.o: auth_pam.c auth_pam.h
	$(CC) $(FLAGS) -c auth_pam.c

MimeType.o: MimeType.c MimeType.h
	$(CC) $(FLAGS) -c MimeType.c 

ChrootHelper.o: ChrootHelper.c ChrootHelper.h
	$(CC) $(FLAGS) -c ChrootHelper.c 

DavProps.o: DavProps.c DavProps.h
	$(CC) $(FLAGS) -c DavProps.c 

Settings.o: Settings.c Settings.h
	$(CC) $(FLAGS) -c Settings.c 

common.o: common.c common.h
	$(CC) $(FLAGS) -c common.c 

server.o: server.c server.h
	$(CC) $(FLAGS) -c server.c 

cgi.o: cgi.c cgi.h
	$(CC) $(FLAGS) -c cgi.c 

Events.o: Events.c Events.h
	$(CC) $(FLAGS) -c Events.c 

VPath.o: VPath.c VPath.h
	$(CC) $(FLAGS) -c VPath.c

UserAdminScreen.o: UserAdminScreen.c UserAdminScreen.h
	$(CC) $(FLAGS) -c UserAdminScreen.c

directory_listing.o: directory_listing.c directory_listing.h
	$(CC) $(FLAGS) -c directory_listing.c 

FileDetailsPage.o: FileDetailsPage.c FileDetailsPage.h
	$(CC) $(FLAGS) -c FileDetailsPage.c 

FileProperties.o: FileProperties.c FileProperties.h
	$(CC) $(FLAGS) -c FileProperties.c 

tar.o: tar.c tar.h
	$(CC) $(FLAGS) -c tar.c 

ID3.o: ID3.c ID3.h
	$(CC) $(FLAGS) -c ID3.c 

upload.o: upload.c upload.h
	$(CC) $(FLAGS) -c upload.c

proxy.o: proxy.c proxy.h
	$(CC) $(FLAGS) -c proxy.c

icecast.o: icecast.c icecast.h
	$(CC) $(FLAGS) -c icecast.c

xssi.o: xssi.c xssi.h
	$(CC) $(FLAGS) -c xssi.c

websocket.o: websocket.c websocket.h
	$(CC) $(FLAGS) -c websocket.c


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

test: 
	-echo "No tests written yet"

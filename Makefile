TGT=dyndns
CC=gcc
PKG=dyndns-2.1.tgz

PREFIX=/usr/local
CONFDIR=${PREFIX}/etc
BINDIR=${PREFIX}/bin
TMP=/tmp

# these defines are for Linux
LIBS=
ARCH=linux

# for Mac OS X and BSD systems that have getifaddr(), uncomment the next line
#ARCH=bsd_with_getifaddrs

# for early BSD systems without getifaddrs(), uncomment the next line
#ARCH=bsd


# for solaris, uncomment the next two lines
# LIBS=-lsocket -lnsl
# ARCH=sun

${TGT}: Makefile ${TGT}.c 
	${CC} -Wall -g -D${ARCH} -DPREFIX=\"${PREFIX}\" ${TGT}.c -o ${TGT} -L/usr/local/lib -lcurl

install: ${TGT} 
	if [ ! -d ${BINDIR} ]; then mkdir -p ${BINDIR};fi
	if [ ! -d ${CONFDIR} ]; then mkdir -p ${CONFDIR};fi
	cp ${TGT} ${TMP}/${TGT}
	${TMP}/${TGT} -C /tmp/dyndns.conf
	if [ -f /tmp/dyndns.conf ]; then mv /tmp/dyndns.conf ${CONFDIR}/dyndns.conf;fi
	if [ -f ${CONFDIR}/dyndns.conf ]; then cp ${TGT} ${BINDIR}/${TGT};fi

package: ${TGT}
	rm  -f *.bak
	mv ${TGT} binaries/${TGT}-`uname -m`
	scp a-k:/local/bin/dyndns binaries/dyndns-`ssh a-k uname -m`
	cd ..; tar zcvf /tmp/${PKG} dyndns-2.1/*
	scp /tmp/${PKG} a-k:/opt/www/${PKG}
	rm /tmp/${PKG}

clean: 
	rm -f *o
	rm -f binaries/*
	rm -f ${TGT}
	rm -f ${BINDIR}/*
	rm -f ${CONFDIR}/dyndns.conf


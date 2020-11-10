#!/bin/sh

set -e

NAME=mcedaemon
VERSION=$1
PACKAGE_REV=$2
FULLNAME=${NAME}-${VERSION}-${PACKAGE_REV}

sudo rm -rf /tmp/${FULLNAME}
mkdir --mode=0755 /tmp/${FULLNAME}
mkdir --mode=0755 /tmp/${FULLNAME}/DEBIAN

cat <<EOF > /tmp/${FULLNAME}/DEBIAN/control
Package: ${NAME}
Version: ${VERSION}
Architecture: amd64
Section: contrib/admin
Priority: optional
Installed-Size: 64
Maintainer: nobody@google.com
Description: mced watches the system for machine check exceptions.
EOF

cp deb.sh /tmp/${FULLNAME}/DEBIAN/postinst
chmod 0775 /tmp/${FULLNAME}/DEBIAN/postinst
cp deb.sh /tmp/${FULLNAME}/DEBIAN/prerm
chmod 0775 /tmp/${FULLNAME}/DEBIAN/prerm

mkdir --mode=0755 /tmp/${FULLNAME}/usr
mkdir --mode=0755 /tmp/${FULLNAME}/usr/bin

cp mced /tmp/${FULLNAME}/usr/bin/
chmod 0755 /tmp/${FULLNAME}/usr/bin/mced
cp mce_listen /tmp/${FULLNAME}/usr/bin/
chmod 0755 /tmp/${FULLNAME}/usr/bin/mce_listen

mkdir --mode=0755 /tmp/${FULLNAME}/etc
mkdir --mode=0755 /tmp/${FULLNAME}/etc/systemd
mkdir --mode=0755 /tmp/${FULLNAME}/etc/systemd/system

cp mced.service /tmp/${FULLNAME}/etc/systemd/system/
chmod 0644 /tmp/${FULLNAME}/etc/systemd/system/mced.service

mkdir --mode=0755 /tmp/${FULLNAME}/etc/mced

cp examples/mce_decode.conf /tmp/${FULLNAME}/etc/mced/
chmod 0644 /tmp/${FULLNAME}/etc/mced/mce_decode.conf
cp examples/mcelog.conf /tmp/${FULLNAME}/etc/mced/
chmod 0644 /tmp/${FULLNAME}/etc/mced/mcelog.conf

chmod o+r -R /tmp/${FULLNAME}
sudo chown root:root -R /tmp/${FULLNAME}

dpkg-deb --build /tmp/${FULLNAME} ./

# dpkg -c archive to list contents
# -e archive [dir] to extract control info
# -x archive dir to exact files
# -I archive to show info about package

sudo rm -rf /tmp/${FULLNAME}

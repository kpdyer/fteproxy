#!/bin/sh

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Assumes Tor is not already installed, will overwrite existing configuration.

FTEPROXY_VERSION=0.2.0
ARCH=`arch`
TMP_DIR=/tmp
CODENAME=`lsb_release -sc`

# download+install tor
sh -c "echo \"deb http://deb.torproject.org/torproject.org $CODENAME main\" >> /etc/apt/sources.list"
sh -c "echo \"deb http://deb.torproject.org/torproject.org experimental-$CODENAME main\" >> /etc/apt/sources.list"
gpg --keyserver keys.gnupg.net --recv 886DDD89
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -
apt-get update
apt-get -y install tor
apt-get -y install deb.torproject.org-keyring
curl https://raw.github.com/kpdyer/fteproxy/master/deployment/tor/torrc.client > /etc/tor/torrc

# download+install fte
cd $TMP_DIR
curl https://fteproxy.org/dist/fteproxy/linux/fteproxy-$FTEPROXY_VERSION-linux-$ARCH.tar.gz > fteproxy-$FTEPROXY_VERSION-linux-$ARCH.tar.gz
tar zxvf fteproxy-$FTEPROXY_VERSION-linux-$ARCH.tar.gz
mkdir -p /usr/local/fteproxy/bin
mkdir -p /usr/local/fteproxy/doc
cp fteproxy-$FTEPROXY_VERSION-linux-$ARCH/fteproxy /usr/local/fteproxy/bin/
cp fteproxy-$FTEPROXY_VERSION-linux-$ARCH/fst* /usr/local/fteproxy/bin/
cp -rfv fteproxy-$FTEPROXY_VERSION-linux-$ARCH/fte /usr/local/fteproxy/bin/
cp fteproxy-$FTEPROXY_VERSION-linux-$ARCH/README.md /usr/local/fteproxy/doc/
cp fteproxy-$FTEPROXY_VERSION-linux-$ARCH/COPYING /usr/local/fteproxy/doc/
rm $TMP_DIR/fteproxy-$FTEPROXY_VERSION-linux-$ARCH.tar.gz
rm -rf $TMP_DIR/fteproxy-$FTEPROXY_VERSION-linux-$ARCH

# restart tor to pickup fte changes
service tor restart

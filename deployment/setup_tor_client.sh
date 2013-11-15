#!/bin/bash

# install fte depedencies
sudo apt-get update
sudo apt-get -y install m4
sudo apt-get -y install git
sudo apt-get -y install python-dev
sudo apt-get -y install python-gmpy
sudo apt-get -y install python-crypto
sudo apt-get -y install python-twisted
sudo apt-get -y install libboost-python-dev
sudo apt-get -y install libboost-system-dev
sudo apt-get -y install libboost-filesystem-dev
sudo apt-get -y install libgmp-dev

# install fte+tor depedencies
sudo apt-get -y install python-pip
sudo pip install obfsproxy
sudo pip install pyptlib
sudo sh -c 'echo "deb http://deb.torproject.org/torproject.org experimental-wheezy main" >> /etc/apt/sources.list'
gpg --keyserver keys.gnupg.net --recv 886DDD89
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -
sudo apt-get update
sudo apt-get -y install tor
sudo apt-get -y install deb.torproject.org-keyring
sudo cp /vagrant/sandbox/fteproxy/tor/torrc.client /etc/tor/torrc

# build+install fte
mkdir /vagrant/sandbox
cd /vagrant/sandbox
git clone https://github.com/redjack/fteproxy.git
cd fteproxy
make all
sudo make install

# restart tor to pickup fte changes
sudo service tor restart

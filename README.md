apt install pkg-config autoconf automake libtool libdb5.3++-dev libdb5.1++ libevent-dev libgmp3-dev

apt-get install libboost-all-dev

apt-get install adjtimex

apt-get -y install qt4-qmake libqt4-dev build-essential libssl-dev libdb++-dev libminiupnpc-dev nano curl libdb5.1 git ntp make g++ gcc autoconf cpp ngrep iftop sysstat iptraf ufw openssh-server nmap libgcrypt20-dev

apt-get install -y libsodium-dev


bitcoin-cli getblocktemplate "{\"rules\":[\"segwit\"]}"

cd depends && make -j4 && cd .. && ./configure --prefix=/root/bitcoin/depends/x86_64-pc-linux-gnu

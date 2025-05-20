# Setting Up Cross Compilers

```sh
# RUN ALL OF THESE AS A PRIVELEGED USER, SINCE WE ARE DOWNLOADING INTO /etc
 
# You're gay if you don't use Debian
apt-get install gcc golang electric-fence
 
mkdir /etc/xcompile
cd /etc/xcompile
 
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/mini-native-armv4l.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/mini-native-i586.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/mini-native-m68k.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/mini-native-mips.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/mini-native-mipsel.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/mini-native-powerpc.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/mini-native-sh4.tar.bz2
wget https://www.uclibc.org/downloads/binaries/0.9.30.1/mini-native-sparc.tar.bz2
 
tar -jxf mini-native-armv4l.tar.bz2
tar -jxf mini-native-i586.tar.bz2
tar -jxf mini-native-m68k.tar.bz2
tar -jxf mini-native-mips.tar.bz2
tar -jxf mini-native-mipsel.tar.bz2
tar -jxf mini-native-powerpc.tar.bz2
tar -jxf mini-native-sh4.tar.bz2
tar -jxf mini-native-sparc.tar.bz2
 
rm *.tar.bz2
mv mini-native-armv4l armv4l
mv mini-native-i586 i586
mv mini-native-m68k m68k
mv mini-native-mips mips
mv mini-native-mipsel mipsel
mv mini-native-powerpc powerpc
mv mini-native-sh4 sh4
mv mini-native-sparc sparc
 
-- END --
 
 
 
 
 
 
# PUT THESE COMMANDS IN THE FILE ~/.bashrc
 
# Cross compiler toolchains
export PATH=$PATH:/etc/xcompile/armv4l/bin
export PATH=$PATH:/etc/xcompile/armv6l/bin
export PATH=$PATH:/etc/xcompile/i586/bin
export PATH=$PATH:/etc/xcompile/m68k/bin
export PATH=$PATH:/etc/xcompile/mips/bin
export PATH=$PATH:/etc/xcompile/mipsel/bin
export PATH=$PATH:/etc/xcompile/powerpc/bin
export PATH=$PATH:/etc/xcompile/powerpc-440fp/bin
export PATH=$PATH:/etc/xcompile/sh4/bin
export PATH=$PATH:/etc/xcompile/sparc/bin
 
# Golang
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/Documents/go
 
```


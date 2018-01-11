QT -= gui

CONFIG += c++11 console
CONFIG -= app_bundle

# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += main.cpp \
    poll_server.cpp

HEADERS += \
    poll_server.h

#***************************************************************
#openssl library

# osx compile guide:
# (https://gist.github.com/tmiz/1441111)
# open a terminal window in OpenSSL-x.x folder
# osx build commands:
# ./Configure darwin64-x86_64-cc -shared
# make clean
# make
macx:LIBS += -L$$PWD/../OpenSSL-1.1.0g/ -lcrypto
macx:LIBS += -L$$PWD/../OpenSSL-1.1.0g/ -lssl
macx:INCLUDEPATH += $$PWD/../OpenSSL-1.1.0g/include/

# windows compile guide:
# install activeperl - https://www.activestate.com/activeperl
# install nasm - http://www.nasm.us/
# go inside OpenSSL-x.x folder from visual studio 2010 command line prompt
# type :
# 1)    perl.exe Configure VC-WIN32
# 2)    nmake clean
# 3)    nmake
# this should compile openssl on windows
windows:LIBS += -L$$PWD/../OpenSSL-1.1.0g/ -llibcrypto
windows:LIBS += -L$$PWD/../OpenSSL-1.1.0g/ -llibssl
windows:INCLUDEPATH += $$PWD/../OpenSSL-1.1.0g/include/

# linux compile guide:
# go inside OpenSSL-x.x folder using the terminal
# type:
# 1)    ./config
# 2)    make clean
# 3)    make
# this should compile openssl on linux
linux:LIBS += -L$$PWD/../OpenSSL-1.1.0g -lcrypto
linux:LIBS += -L$$PWD/../OpenSSL-1.1.0g -lssl
linux:INCLUDEPATH += $$PWD/../OpenSSL-1.1.0g/include
#***************************************************************


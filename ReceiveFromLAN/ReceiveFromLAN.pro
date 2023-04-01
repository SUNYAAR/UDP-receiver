#-------------------------------------------------
#
# Project created by QtCreator 2021-03-08T12:51:34
#
#-------------------------------------------------

QT       += core gui concurrent
QT       += network
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = ReceiveFromLAN
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS
CONFIG += c++14
# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

# Winpcap -----------------------------------------------------------
LIBS += -L$$PWD/../WpdPack/Lib/x64 -lwpcap -lpacket -lws2_32
INCLUDEPATH += $$PWD/../WpdPack/Include

DEFINES += WPCAP

DEFINES += HAVE_REMOTE
#------------------------------

SOURCES += main.cpp \
           log.cpp \
           mainwindow.cpp \
           pcapwrapper.cpp \
           winpcap.cpp

HEADERS += mainwindow.h \
    log.h \
    pcapwrapper.h \
    winpcap.h

FORMS += \
        mainwindow.ui


TEMPLATE = app
CONFIG += console
CONFIG -= qt

win32 {
    INCLUDEPATH += "../src/libs"
    LIBS +=  ../src/libs/libspw_eth_win.a

    INCLUDEPATH += "../src/libs/winpcap/Include"
    INCLUDEPATH += "../src/libs/winpcap/Lib"
    LIBS += -L ../src/libs/winpcap/Lib -lwpcap
    LIBS += -lws2_32
}

unix {
    INCLUDEPATH += "../src/libs"
    LIBS +=  ../src/libs/libspw_eth_unix.a
}

HEADERS += \
    ../src/headers/spw_eth_structure.h \
    ../src/headers/spw_eth_print.h \
    ../src/headers/spw_eth.h
SOURCES += \
    ../demo/spw_eth_test.c

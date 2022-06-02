QT       += core gui sql printsupport

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    aimodule.cpp \
    cleanermodule.cpp \
    detectionmodule.cpp \
    main.cpp \
    vaitp.cpp

HEADERS += \
    aimodule.h \
    cleanermodule.h \
    detectionmodule.h \
    vaitp.h

FORMS += \
    vaitp.ui

TRANSLATIONS += \
    vaitp_pt_PT.ts

OTHER_FILES += \
    vaitp.db

CONFIG += lrelease
CONFIG += embed_translations


# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    resources.qrc

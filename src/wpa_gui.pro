TEMPLATE	= app
TARGET		= wpa-cute
LANGUAGE	= C++
TRANSLATIONS	= lang/wpa_gui_de.ts
QT += widgets svg

CONFIG	+= qt warn_on debug_and_release

DEFINES += CONFIG_CTRL_IFACE
DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x050F00
QMAKE_CXXFLAGS += -Wformat-truncation=0

win32 {
  LIBS += -lws2_32 -static
  DEFINES += CONFIG_NATIVE_WINDOWS CONFIG_CTRL_IFACE_NAMED_PIPE
  SOURCES += ../wpa_supplicant/src/utils/os_win32.c
} else:win32-g++ {
  # cross compilation to win32
  LIBS += -lws2_32 -static -mwindows
  DEFINES += CONFIG_NATIVE_WINDOWS CONFIG_CTRL_IFACE_NAMED_PIPE
  SOURCES += ../wpa_supplicant/src/utils/os_win32.c
  RESOURCES += icons_png.qrc
} else:win32-x-g++ {
  # cross compilation to win32
  LIBS += -lws2_32 -static -mwindows
  DEFINES += CONFIG_NATIVE_WINDOWS CONFIG_CTRL_IFACE_NAMED_PIPE
  DEFINES += _X86_
  SOURCES += ../wpa_supplicant/src/utils/os_win32.c
  RESOURCES += icons_png.qrc
} else {
  DEFINES += CONFIG_CTRL_IFACE_UNIX
  SOURCES += ../wpa_supplicant/src/utils/os_unix.c
}

INCLUDEPATH	+= . .. ../wpa_supplicant/src ../wpa_supplicant/src/utils

HEADERS	+= wpamsg.h \
	wpagui.h \
	eventhistory.h \
	scanresults.h \
	scanresultsitem.h \
	signalbar.h \
	wpsdialog.h \
	networkconfig.h \
	addinterface.h \
	peers.h \
	stringquery.h \
	about.h

SOURCES	+= main.cpp \
	wpagui.cpp \
	eventhistory.cpp \
	scanresults.cpp \
	scanresultsitem.cpp \
	wpsdialog.cpp \
	signalbar.cpp \
	networkconfig.cpp \
	addinterface.cpp \
	peers.cpp \
	stringquery.cpp \
	about.cpp \
	../wpa_supplicant/src/common/wpa_ctrl.c

RESOURCES += icons.qrc

FORMS	= wpagui.ui \
	eventhistory.ui \
	scanresults.ui \
	wpsdialog.ui \
	networkconfig.ui \
	peers.ui \
	about.ui

unix {
  UI_DIR = .ui
  MOC_DIR = .moc
  OBJECTS_DIR = .obj
}

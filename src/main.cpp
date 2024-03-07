/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018, 2022, 2024 loh.tar@googlemail.com
 *
 * wpa_gui - Application startup
 * Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#ifdef CONFIG_NATIVE_WINDOWS
#include <winsock.h>
#endif /* CONFIG_NATIVE_WINDOWS */

#include <QApplication>
#include <QProcess>
#include <QtCore/QLibraryInfo>
#include <QtCore/QTranslator>

#include "about.h"
#include "wpagui.h"

WpaGuiApp::WpaGuiApp(int& argc, char** argv)
         : QApplication(argc, argv)
         , argc(argc)
         , argv(argv)
         , mainWindow(NULL) {

}

#if !defined(QT_NO_SESSIONMANAGER) && QT_VERSION < 0x050000
void WpaGuiApp::saveState(QSessionManager& manager) {

	QApplication::saveState(manager);
	mainWindow->saveState();
}
#endif

#ifndef CONFIG_NATIVE_WINDOWS
#include <QTextStream>
// Thanks to https://stackoverflow.com/a/3886128
QTextStream& qStdOut() {

    static QTextStream ts(stdout);
    return ts;
}
#endif

int main(int argc, char* argv[]) {

	WpaGuiApp app(argc, argv);
	QTranslator translator;
	QString locale;
	QString resourceDir;
	int ret;

#ifndef CONFIG_NATIVE_WINDOWS
// It seems console output on Windows need more effort
// feel free to fix it https://stackoverflow.com/q/3360548
	for (int i = 1; i < argc; i++) {
		QString arg(argv[i]);
		if (arg.startsWith("-h") || arg.startsWith("-?") ) {
			qStdOut() << About::slogan() << "\n";
			qStdOut() << "version : " ProjVersion ", " ProjRelease "\n";
			qStdOut() << "usage   : wpa-cute [-i <ifname>][-m <seconds>][-p <dir>][-t][-p][-q][-N][-W]\n";
			qStdOut() << "help    : wpa-cute --h\n";
			qStdOut() << "license : wpa-cute --l\n";
			return 0;
		}
		if (arg.startsWith("--h")) {
			// To avoid redundance and list all stuff again here, call our neat man page
			// But it would be nicer to print some data by an option listed currently
			// in WpaGui::helpAbout()
			QProcess::execute("man", {"wpa-cute"});
			return 0;
		}
		if (arg.startsWith("--l")) {
			qStdOut() << About::license() << "\n";
			return 0;
		}
	}
#endif

	locale = QLocale::system().name();
	resourceDir = QLibraryInfo::location(QLibraryInfo::TranslationsPath);
	if (!translator.load("wpa_gui_" + locale, resourceDir))
		std::ignore = translator.load("wpa_gui_" + locale, "lang");
	app.installTranslator(&translator);

	WpaGui w(&app);

#ifdef CONFIG_NATIVE_WINDOWS
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 0), &wsaData)) {
		/* printf("Could not find a usable WinSock.dll\n"); */
		return -1;
	}
#endif /* CONFIG_NATIVE_WINDOWS */

	app.mainWindow = &w;

	ret = app.exec();

#ifdef CONFIG_NATIVE_WINDOWS
	WSACleanup();
#endif /* CONFIG_NATIVE_WINDOWS */

	return ret;
}

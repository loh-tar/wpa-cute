/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018 loh.tar@googlemail.com
 *
 * wpaCute - About data
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

// The naming of this file "about.h" may a litte confusing,
// it is NOT related to ui_about.h

#ifndef ABOUT_H
#define ABOUT_H

#include <QString>

#define ProjAppName "wpaCute"
#define ProjVersion "0.8"
#define ProjRelease "Sep 2018"


namespace About {
	QString slogan();
	QString copyright();
// 	    QString text(const QString& see);
	QString text(const QString& see);
	QString license();
}

#endif /* ABOUT_H */

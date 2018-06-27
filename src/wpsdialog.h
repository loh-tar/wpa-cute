/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018 loh.tar@googlemail.com
 *
 * Based on ideas by Jouni Malinen <j@w1.fi> and contributors
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#ifndef WPSDIALOG_H
#define WPSDIALOG_H

#include <QObject>
#include "ui_wpsdialog.h"

class WpaGui;

class WpsDialog : public QDialog, public Ui::WpsDialog
{
	Q_OBJECT

public:
	WpsDialog(WpaGui* _wpagui);
	~WpsDialog();

	            void setNetworkIds(const QString& ssid, const QString& bssid);
	            void activePbcAvailable(const QString& _ssid = "", const QString& _bssid = "");
	            void pbcOverlapDetected();

public slots:
	virtual     void reject();

protected slots:
	virtual     void languageChange();

	            void tabChanged();
	            void wpsApPinChanged(const QString &text);
	            void wpsPbcButtonClicked();
	            void wpsApPinButtonClicked();
	            void wpsPinButtonClicked();

private:
	         WpaGui* wpagui;
	            bool wpsPbcOverlap;
};

#endif /* WPSDIALOG_H */

/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018 loh.tar@googlemail.com
 *
 * wpa_gui - ScanResults class
 * Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#ifndef SCANRESULTS_H
#define SCANRESULTS_H

#include <QObject>
#include "ui_scanresults.h"

class WpaGui;

class ScanResults : public QDialog, public Ui::ScanResults
{
	Q_OBJECT

public:
	ScanResults(WpaGui* _wpagui);
	~ScanResults();

public slots:
	virtual void requestScan();
	virtual void updateResults();

protected slots:
	virtual void languageChange();
	virtual void networkSelected(QTreeWidgetItem* curr);
	virtual void addNetwork();
	virtual void showWpsDialog();

private:
	WpaGui*             wpagui;
	QString             selectedNetworkId;
	QTreeWidgetItem*    selectedNetwork;
};

#endif /* SCANRESULTS_H */

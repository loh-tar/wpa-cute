/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018 loh.tar@googlemail.com
 *
 * wpa_gui - NetworkConfig class
 * Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#ifndef NETWORKCONFIG_H
#define NETWORKCONFIG_H

#include <QObject>
#include "ui_networkconfig.h"

class WpaGui;

class NetworkConfig : public QDialog, public Ui::NetworkConfig
{
	Q_OBJECT

public:
	NetworkConfig(WpaGui *parent);
	~NetworkConfig();

	virtual void paramsFromScanResults(QTreeWidgetItem *sel);
	virtual  int setNetworkParam(int id, const QString &variable,
                               const QString &value, bool quote = false);
	virtual void paramsFromConfig(int network_id);
	virtual void newNetwork();

public slots:
	virtual void authChanged(int sel);
	virtual void addNetwork();
	virtual void encrChanged(const QString &sel);
	virtual void writeWepKey(int network_id, QLineEdit *edit, int id);
	virtual void removeNetwork();
	virtual void eapChanged(int sel);

protected slots:
	virtual void languageChange();

private:
	WpaGui *wpagui;
	int edit_network_id;
	bool new_network;
	QString bssid;

	virtual void wepEnabled(bool enabled);
	virtual void getEapCapa();
};

#endif /* NETWORKCONFIG_H */

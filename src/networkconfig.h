/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018, 2022 loh.tar@googlemail.com
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
	             NetworkConfig(WpaGui* parent);
	            ~NetworkConfig();

	        void editNetwork(const QString& id, const QString& bssid = "");
	        void newNetwork(QTreeWidgetItem* sel);
	        void newNetwork();

protected slots:
	        void languageChange();

	        void authChanged(int sel);
	        void applyNetworkChanges();
	        void encrChanged(const QString& sel);
	        void writeWepKey(const QString& id, QLineEdit* edit, int keyId);
	        void removeNetwork();
	        void eapChanged(int sel);
	        void pullTheAce();

private:
	         int setNetworkParam(const QString& id, const QString& parm
	                           , const QString& val, bool quote = false);
	        void wepEnabled(bool enabled);
	        void getEapCapa();

	     WpaGui* wpagui;
	     QString networkId;
	     QString aceInTheHoleId;

};

#endif /* NETWORKCONFIG_H */

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

	        void editNetwork(int network_id, const QString& bssid = "");
	        void newNetwork(QTreeWidgetItem *sel);
	        void newNetwork();

public slots:
	        void authChanged(int sel);
	        void applyNetworkChanges();
	        void encrChanged(const QString &sel);
	        void writeWepKey(int network_id, QLineEdit *edit, int id);
	        void removeNetwork();
	        void eapChanged(int sel);

protected slots:
	virtual void languageChange();
	        void pullTheAce();

private:
	         int setNetworkParam(int id, const QString &variable, const QString &value, bool quote = false);
	        void wepEnabled(bool enabled);
	        void getEapCapa();

	     WpaGui* wpagui;
	         int edit_network_id;
	        bool new_network;
	     QString aceInTheHoleId;

};

#endif /* NETWORKCONFIG_H */

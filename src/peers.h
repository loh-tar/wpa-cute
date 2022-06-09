/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018, 2022 loh.tar@googlemail.com
 *
 * wpa_gui - Peers class
 * Copyright (c) 2009-2010, Atheros Communications
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#ifndef PEERS_H
#define PEERS_H

#include <QObject>
#include <QStandardItemModel>
#include "wpamsg.h"
#include "ui_peers.h"

class WpaGui;

class Peers : public QDialog, public Ui::Peers
{
	Q_OBJECT

public:
	Peers(WpaGui* _wpagui);
	~Peers();

	void event_notify(WpaMsg msg);

public slots:
	        void context_menu(const QPoint &pos);
	        void enter_pin();
	        void connect_pbc();
	        void learn_ap_config();
	        void ctx_refresh();
	        void ctx_p2p_start();
	        void ctx_p2p_stop();
	        void ctx_p2p_listen();
	        void ctx_p2p_start_group();
	        void ctx_p2p_remove_group();
	        void ctx_p2p_connect();
	        void ctx_p2p_req_pin();
	        void ctx_p2p_show_pin();
	        void ctx_p2p_display_pin();
	        void ctx_p2p_display_pin_pd();
	        void ctx_p2p_enter_pin();
	        void properties();
	        void ctx_hide_ap();
	        void ctx_show_ap();
	        void ctx_p2p_show_passphrase();
	        void ctx_p2p_start_persistent();
	        void ctx_p2p_invite();
	        void ctx_p2p_delete();

protected slots:
	        void languageChange();
	        void closeEvent(QCloseEvent *event);

private:
	void add_station(QString info);
	void add_stations();
	void add_single_station(const char* addr);
	bool add_bss(const QString& cmd);
	void remove_bss(int id);
	void add_scan_results();
	void add_persistent(int id, const char* ssid, const char* bssid);
	void add_persistent_groups();
	void update_peers();
	QStandardItem* find_addr(QString addr);
	QStandardItem* find_addr_type(QString addr, int type);
	void add_p2p_group_client(QStandardItem *parent, QString params);
	QStandardItem* find_uuid(QString uuid);
	void done(int r);
	void remove_enrollee_uuid(QString uuid);
	QString ItemType(int type);
	void enable_persistent(int id);

	WpaGui* wpagui;
	QStandardItemModel model;
	QIcon* default_icon;
	QIcon* ap_icon;
	QIcon* laptop_icon;
	QIcon* group_icon;
	QIcon* invitation_icon;
	QStandardItem* ctx_item;

	bool hide_ap;
};

#endif /* PEERS_H */

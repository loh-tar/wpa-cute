/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018 loh.tar@googlemail.com
 *
 * wpa_gui - WpaGui class
 * Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#ifndef WPAGUI_H
#define WPAGUI_H

#include <QSystemTrayIcon>
#include <QObject>
#include "ui_wpagui.h"


#define ProjAppName "wpaCute"
#define ProjVersion "0.7"
#define ProjRelease "Jun 2018"


class UserDataRequest;
class AddInterface;

class WpaGuiApp : public QApplication
{
	Q_OBJECT
public:
	WpaGuiApp(int &argc, char **argv);

#if !defined(QT_NO_SESSIONMANAGER) && QT_VERSION < 0x050000
	virtual void saveState(QSessionManager &manager);
#endif

	WpaGui *w;
	int argc;
	char **argv;
};

class WpaGui : public QMainWindow, public Ui::WpaGui
{
	Q_OBJECT

public:

	enum TrayIconType {
		TrayIconNone = 0,
		TrayIconError,
		TrayIconOffline,
		TrayIconInactive,
		TrayIconScanning,
		TrayIconAcquiring,
		TrayIconConnected,
		TrayIconSignalNone,
		TrayIconSignalWeak,
		TrayIconSignalOk,
		TrayIconSignalGood,
		TrayIconSignalExcellent,
	};

	enum WpaStateType {
		WpaFatal = 0,
		WpaUnknown,
		WpaNotRunning,
		WpaRunning,
		WpaAuthenticating,
		WpaAssociating,
		WpaAssociated,
		Wpa4WayHandshake,
		WpaGroupHandshake,
		WpaWait4Registrar,
		WpaInactive,
		WpaScanning,
		WpaDisconnected,
		WpaLostSignal,
		WpaCompleted
	};

	enum DogBreed {
		PomDog         = 1000,
		BorderCollie   = 2500,
		BassetHound    = 9000,
		SnoozingDog    = 20 * 1000
	};

	WpaGui(QApplication *app, QWidget *parent = 0, const char *name = 0,
	       Qt::WindowFlags fl = 0);
	~WpaGui();

	virtual int ctrlRequest(const char *cmd, char *buf, size_t *buflen);
	virtual void editNetwork(const QString &sel);
	virtual void removeNetwork(const QString &sel);
	virtual void enableNetwork(const QString &sel);
	virtual void disableNetwork(const QString &sel);
	virtual int getNetworkDisabled(const QString &sel);
	void setBssFromScan(const QString &bssid);
#ifndef QT_NO_SESSIONMANAGER
	void saveState();
#endif

public slots:
	virtual void parse_argv();

	virtual void updateStatus(bool changed = true);
	virtual void updateNetworks(bool changed = true);
	virtual void updateSignalMeter();

	virtual void disconnReconnect();
	virtual void wpsDialog();
	virtual void scan();
	virtual void peersDialog();
	virtual void eventHistory();
	virtual void saveConfig();
	virtual void reloadConfig();

	virtual void addNetwork();
	virtual void editListedNetwork();
	virtual void enableAllNetworks();
	virtual void disableAllNetworks();
	virtual void removeListedNetwork();
	virtual void removeAllNetworks();

	virtual void disableNotifier(bool yes);
	virtual void enablePolling(bool yes);

	virtual void helpIndex();
	virtual void helpContents();
	virtual void helpAbout();

	virtual void ping();
	virtual void processMsg(char *msg);
	virtual void processCtrlReq(const char *req);
	virtual void receiveMsgs();
	virtual void networkSelectionChanged();

	virtual void selectAdapter(const QString &sel);
	virtual void disEnableNetwork();
	virtual void showTrayMessage(const QString &msg
	           , QSystemTrayIcon::MessageIcon type = QSystemTrayIcon::Information
	           , int sec = 5);
	virtual void updateTrayIcon(TrayIconType type);
	virtual void updateTrayToolTip(const QString &msg);
	virtual QIcon loadThemedIcon(const QStringList &names,
	                             const QIcon &fallback);
	virtual void tabChanged(int index);
	virtual void wpsPbc();
	virtual void wpsGeneratePin();
	virtual void wpsApPinChanged(const QString &text);
	virtual void wpsApPin();
#ifdef CONFIG_NATIVE_WINDOWS
	virtual void startService();
	virtual void stopService();
	virtual void addInterface();
#endif /* CONFIG_NATIVE_WINDOWS */

protected slots:
	virtual void showTrayStatus();
	virtual void languageChange();
	virtual void trayActivated(QSystemTrayIcon::ActivationReason how);
	virtual void closeEvent(QCloseEvent *event);
	virtual void showEvent(QShowEvent *event);

private:
	virtual void requestNetworkChange(const QString &req, const QString &sel);
	virtual void logHint(const QString &hint);

	virtual void letTheDogOut(int dog, bool yes);
	virtual void letTheDogOut(int dog = PomDog);
	virtual void letTheDogOut(bool yes = true);

	        void wpaStateTranslate(const char *state);
	        void setState(const WpaStateType state);


	QSet<int> tally;
	WpaStateType wpaState;

	ScanResults *scanres;
	Peers *peers;

	char *ctrl_iface;
	EventHistory *eh;
	struct wpa_ctrl *ctrl_conn;
	QSocketNotifier *msgNotifier;
	QTimer *watchdogTimer;
	WpaMsgList msgs;
	char *ctrl_iface_dir;
	struct wpa_ctrl *monitor_conn;
	UserDataRequest *udr;
	QMenu *tray_menu;
	QSystemTrayIcon *tray_icon;
	TrayIconType currentIconType;
	void createTrayIcon(bool);

	int openCtrlConnection(const char *ifname);

	QString bssFromScan;

	void stopWpsRun(bool success);

	QTimer *signalMeterTimer;
	int signalMeterInterval;

#ifdef CONFIG_NATIVE_WINDOWS
	QAction *fileStartServiceAction;
	QAction *fileStopServiceAction;

	bool serviceRunning();
	QAction *addInterfaceAction;
	AddInterface *add_iface;
#endif /* CONFIG_NATIVE_WINDOWS */

	QApplication *app;
};

#endif /* WPAGUI_H */

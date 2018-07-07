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

#include <QObject>
#include <QPointer>
#include <QSocketNotifier>
#include <QSystemTrayIcon>
#include <QTimer>

#include "ui_wpagui.h"
#include "wpamsg.h"

class AddInterface;
class EventHistory;
class Peers;
class ScanResults;
class WpaGui;
class WpsDialog;


#define ProjAppName "wpaCute"
#define ProjVersion "0.7"
#define ProjRelease "Jun 2018"


class WpaGuiApp : public QApplication
{
	Q_OBJECT
public:
	WpaGuiApp(int& argc, char** argv);

#if !defined(QT_NO_SESSIONMANAGER) && QT_VERSION < 0x050000
	virtual void saveState(QSessionManager& manager);
#endif

	int     argc;
	char**  argv;
	WpaGui* mainWindow;
};

class WpaGui : public QMainWindow, public Ui::WpaGui
{
	Q_OBJECT
	friend class ScanResults;

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
		WpaObscure,
		WpaRunning,
		WpaAuthenticating,
		WpaAssociating,
		WpaAssociated,
		Wpa4WayHandshake,
		WpaGroupHandshake,
		WpaWait4Registrar,
		WpaInactive,
		WpaWpsRunning,
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

	WpaGui(WpaGuiApp *app
	     , QWidget *parent = 0
	     , const char *name = 0
	     , Qt::WindowFlags fl = 0);

	~WpaGui();

	virtual int ctrlRequest(const QString &cmd, char *buf, const size_t buflen);
	virtual int ctrlRequest(const QString &cmd);

	virtual void editNetwork(const QString &id, const QString &bssid = "");
	virtual void removeNetwork(const QString &sel);
	virtual void enableNetwork(const QString &sel);
	virtual void disableNetwork(const QString &sel);
	virtual  int getNetworkDisabled(const QString &sel);
#ifndef QT_NO_SESSIONMANAGER
	void saveState();
#endif

public slots:
	virtual void updateStatus(bool needsUpdate = true);
	virtual void updateNetworks(bool changed = true);
	virtual void updateSignalMeter();

	virtual void disconnReconnect();

	virtual void showScanWindow();
	virtual void showPeersWindow();
	virtual void showEventHistoryWindow();
	virtual void showWpsWindow();

	virtual void saveConfig();
	virtual void reloadConfig();
	virtual void configIsChanged(bool changed = true);

	virtual void addNetwork();
	virtual void editListedNetwork();
	virtual void chooseNetwork();
	virtual void chooseNetwork(const QString& id, const QString& ssid);
	virtual void disEnableNetwork();
	virtual void enableAllNetworks();
	virtual void disableAllNetworks();
	virtual void removeListedNetwork();
	virtual void removeAllNetworks();
	virtual void scan4Networks();

	virtual void disableNotifier(bool yes);
	virtual void enablePolling(bool yes);

	virtual void helpIndex();
	virtual void helpContents();
	virtual void helpAbout();

	virtual void ping();
	virtual void processMsg(char *msg);
	virtual void processCtrlReq(const QString& req);
	virtual void receiveMsgs();
	virtual void networkSelectionChanged();

	virtual void selectAdapter(const QString &sel);
	virtual void trayMessage(const QString &msg
	           , bool logIt = false
	           , QSystemTrayIcon::MessageIcon type = QSystemTrayIcon::Information
	           , int sec = 5);
	virtual void updateTrayIcon(TrayIconType type);
	virtual void updateTrayToolTip(const QString &msg);
	virtual QIcon loadThemedIcon(const QStringList &names,
	                             const QIcon &fallback);

	        void wpsPbc(const QString& bssid = "");
	        void wpsApPin(const QString& bssid, const QString& pin);
	     QString wpsGeneratePin(const QString& bssid);
	        void wpsStart();
	        void wpsStop(const QString& reason);
	        void wpsCancel();
#ifdef CONFIG_NATIVE_WINDOWS
	virtual void startService();
	virtual void stopService();
	virtual void addInterface();
#endif /* CONFIG_NATIVE_WINDOWS */

protected slots:
	        void assistanceDogOffice();
	        void restoreStatusHint();
	        void restoreConfigUpdates();
	virtual void showTrayStatus();
	virtual void languageChange();
	virtual void trayActivated(QSystemTrayIcon::ActivationReason how);
	virtual void closeEvent(QCloseEvent *event);
	virtual void showEvent(QShowEvent *event);

private:

	enum DialogType {
		ScanWindow,
		PeersWindow,
		EventHistWindow,
		WpsWindow
	};

	        int  openCtrlConnection(const char *ifname);

	virtual void requestNetworkChange(const QString &req, const QString &sel);
	virtual void logHint(const QString &hint);

	virtual void letTheDogOut(int dog, bool yes);
	virtual void letTheDogOut(int dog = PomDog);
	virtual void letTheDogOut(bool yes = true);
	        void assistanceDogNeeded(bool needed = true);

	        void wpaStateTranslate(const QString& state);
	        bool checkUpdateConfigSetting(const int config = -1);
	        void blockConfigUpdates(bool blocking = true);
	        void setState(const WpaStateType state);

	        void parseArgCV(WpaGuiApp *app);
	        void newDialog(DialogType type, QDialog* window);
	        void closeDialog(QDialog* window);


	QSet<int> tally;
	WpaStateType wpaState;

	QPointer<ScanResults>      scanWindow;
	QPointer<Peers>            peersWindow;
	QPointer<EventHistory>     eventHistoryWindow;
	QPointer<WpsDialog>        wpsWindow;

	QTimer*                    assistanceDog;
	QTimer*                    watchdogTimer;
	QTimer*                    restoreStatusHintTimer;

	char*                      ctrl_iface;
	char*                      ctrl_iface_dir;
	struct wpa_ctrl*           ctrl_conn;
	struct wpa_ctrl*           monitor_conn;
	QPointer<QSocketNotifier>  msgNotifier;
	WpaMsgList                 msgs;
	QMenu *tray_menu;
	QSystemTrayIcon *tray_icon;
	TrayIconType currentIconType;
	void createTrayIcon(bool);

	QTimer *signalMeterTimer;
	int signalMeterInterval;

#ifdef CONFIG_NATIVE_WINDOWS
	QAction *fileStartServiceAction;
	QAction *fileStopServiceAction;

	bool serviceRunning();
	QAction *addInterfaceAction;
	AddInterface *add_iface;
#endif /* CONFIG_NATIVE_WINDOWS */
};

#endif /* WPAGUI_H */

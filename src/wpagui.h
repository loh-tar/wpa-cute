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

class EventHistory;
class Peers;
class ScanResults;
class WpaGui;
class WpsDialog;


class WpaGuiApp : public QApplication
{
	Q_OBJECT
public:
	WpaGuiApp(int& argc, char** argv);

#if !defined(QT_NO_SESSIONMANAGER) && QT_VERSION < 0x050000
	        void saveState(QSessionManager& manager);
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
		WpaDisabled,
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

	enum NetworkListColumn {
		NLColId = 0,
		NLColIdVisible,
		NLColSsid,
		NLColBssid,
		NLColPrio,
		NLColFlags,
	};

	enum DogBreed {
		NoDog          = 0,
		PomDog         = 1000,
		BorderCollie   = 2500,
		BassetHound    = 9000,
		SnoozingDog    = 20 * 1000
	};

	WpaGui(WpaGuiApp *app
	     , QWidget*  parent = 0
	     , const char* name = 0
	     , Qt::WindowFlags fl = Qt::Widget);

	~WpaGui();

	         int ctrlRequest(const QString& cmd, char* buf, const size_t buflen);
	         int ctrlRequest(const QString& cmd);
	     QString getLastCtrlRequestResult();
	         int getLastCtrlRequestReturnValue();
	     QString getData(const QString& cmd);
	     QString getIdFlag(const QString& id);

	        void editNetwork(const QString& id, const QString& bssid = "");
	        void removeNetwork(const QString& sel);
	        void enableNetwork(const QString& sel);
	        void disableNetwork(const QString& sel);
	         int getNetworkDisabled(const QString& sel);
#ifndef QT_NO_SESSIONMANAGER
	        void saveState();
#endif

public slots:
	        void updateStatus(bool needsUpdate = true);
	        void updateNetworks(bool changed = true);
	        void updateSignalMeter();

	        void disconnReconnect();

	        void showScanWindow();
	        void showPeersWindow();
	        void showEventHistoryWindow();
	        void showWpsWindow();

	        void saveConfig();
	        void reloadConfig();
	        void configIsChanged(bool changed = true);

	        void addNetwork();
	        void editListedNetwork();
	        void chooseNetwork();
	        void chooseNetwork(const QString& id, const QString& ssid);
	        void disEnableNetwork();
	        void enableAllNetworks();
	        void disableAllNetworks();
	        void removeListedNetwork();
	        void removeAllNetworks();
	        void scan4Networks();

	        void disableNotifier(bool yes);
	        void enablePolling(bool yes);

	        void helpIndex();
	        void helpContents();
	        void helpAbout();

	        void ping();
	        void processMsg(char* msg);
	        void processCtrlReq(const QString& req);
	        void receiveMsgs();
	        void networkSelectionChanged();

	        void selectAdapter(const QString& sel);
	        void trayMessage(const QString& msg
	                       , bool logIt = false
	                       , QSystemTrayIcon::MessageIcon type = QSystemTrayIcon::Information
	                       , int sec = 5);
	        void updateTrayIcon(TrayIconType type);
	        void updateTrayToolTip(const QString& msg);
	       QIcon loadThemedIcon(const QStringList& names);

	        void wpsPbc(const QString& bssid = "");
	        void wpsApPin(const QString& bssid, const QString& pin);
	     QString wpsGeneratePin(const QString& bssid);
	        void wpsStart();
	        void wpsStop(const QString& reason);
	        void wpsCancel();
#ifdef CONFIG_NATIVE_WINDOWS
	        void startService();
	        void stopService();
	        void addInterface();
#endif /* CONFIG_NATIVE_WINDOWS */

protected slots:
	        void assistanceDogOffice();
	        void restoreStatusHint();
	        void restoreConfigUpdates();
	        void showTrayStatus();
	        void languageChange();
	        void trayActivated(QSystemTrayIcon::ActivationReason how);
	        void closeEvent(QCloseEvent* event);
	        void showEvent(QShowEvent* event);

private:

	enum DialogType {
		ScanWindow,
		PeersWindow,
		EventHistWindow,
		WpsWindow
	};

	        int  openCtrlConnection(const QString& ifname);

	        void requestNetworkChange(const QString& req, const QString& sel);
	        void logHint(const QString& hint);

	        void letTheDogOut(int dog, bool yes);
	        void letTheDogOut(int dog);
	        void letTheDogOut(bool yes = true);
	        void assistanceDogNeeded(bool needed = true);

	        void wpaStateTranslate(const QString& state);
	        bool checkUpdateConfigSetting(const int config = -1);
	        void blockConfigUpdates(bool blocking = true);
	        void setState(const WpaStateType state);

	        void parseArgCV(WpaGuiApp *app);
	        void createTrayIcon(bool);
	        void newDialog(DialogType type, QDialog* window);
	        void closeDialog(QDialog* window);


	QSet<int>                  tally;
	WpaStateType               wpaState;

	QPointer<QSystemTrayIcon>  trayIcon;
	TrayIconType               currentIconType;

	QPointer<ScanResults>      scanWindow;
	QPointer<Peers>            peersWindow;
	QPointer<EventHistory>     eventHistoryWindow;
	QPointer<WpsDialog>        wpsWindow;

	QTimer                     watchdogTimer;
	QTimer                     signalMeterTimer;
	QTimer                     restoreStatusHintTimer;
	QTimer                     assistanceDog;

	QString                    ctrlInterface;
	QString                    ctrlInterfaceDir;
	struct wpa_ctrl*           ctrl_conn;
	struct wpa_ctrl*           monitor_conn;
	QPointer<QSocketNotifier>  msgNotifier;
	WpaMsgList                 msgs;
	QString                    lastCtrlRequestResult;
	int                        lastCtrlRequestReturnValue;


#ifdef CONFIG_NATIVE_WINDOWS
	bool                       serviceRunning();
#endif /* CONFIG_NATIVE_WINDOWS */
};

#endif /* WPAGUI_H */

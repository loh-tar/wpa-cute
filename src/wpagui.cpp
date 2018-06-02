/*
 * wpa_gui - WpaGui class
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifdef CONFIG_NATIVE_WINDOWS
#include <windows.h>
#include "addinterface.h"
#endif /* CONFIG_NATIVE_WINDOWS */

#include <cstdio>
#include <unistd.h>
#include <QMessageBox>
#include <QCloseEvent>
#include <QImageReader>
#include <QSettings>
#include <QScrollBar>

#include "wpagui.h"
#include "dirent.h"
#include "common/wpa_ctrl.h"
#include "userdatarequest.h"
#include "networkconfig.h"


#ifndef QT_NO_DEBUG
#define debug(M, ...) qDebug("DEBUG %d: " M, __LINE__, ##__VA_ARGS__)
#else
#define debug(M, ...) do {} while (0)
#endif

enum TallyType {
	AckTrayIcon,
	ConnectedToService,     // FIXME Windows only, using wpaState possible ?
	InTray,
	NetworkNeedsUpdate,
	QuietMode,
	StartInTray,
	StatusNeedsUpdate,
	WpsRunning,
};

WpaGui::WpaGui(QApplication *_app
             , QWidget *parent, const char *
             , Qt::WindowFlags)
      : QMainWindow(parent), app(_app)
{
	setupUi(this);
	this->setWindowFlags(Qt::Dialog);
	logHint(tr("Start-up at %1")
	       .arg(QDateTime::currentDateTime()
	       .toString("dddd, yyyy-MM-dd")));


// Force polling when QSocketNotifier is not supported
// FIXME Not sure if this is all enough here.
//       The orig code has had this check at the beginning of ping()
// #ifdef CONFIG_CTRL_IFACE_NAMED_PIPE
// *
// * QSocketNotifier cannot be used with Windows named pipes, so use a
// * timer to check for received messages for now. This could be
// * optimized be doing something specific to named pipes or Windows
// * events, but it is not clear what would be the best way of doing that
// * in Qt.
// */
// receiveMsgs();
// #endif /* CONFIG_CTRL_IFACE_NAMED_PIPE */
#if !defined(CONFIG_CTRL_IFACE_UNIX) && !defined(CONFIG_CTRL_IFACE_UDP)
	logHint("QSocketNotifier not supported, polling is mandatory");
	enablePollingAction->setEnabled(false);
	enablePollingAction->setChecked(true);
	disableNotifierAction->setEnabled(false);
	disableNotifierAction->setChecked(true);
#endif

	disconReconButton->setDefaultAction(disconReconAction);
	scanButton->setDefaultAction(scanAction);
	addNetworkButton->setDefaultAction(networkAddAction);
	editNetworkButton->setDefaultAction(networkEditAction);
	removeNetworkButton->setDefaultAction(networkRemoveAction);
	disEnableNetworkButton->setDefaultAction(networkDisEnableAction);

#ifdef CONFIG_NATIVE_WINDOWS
	fileStopServiceAction = new QAction(this);
	fileStopServiceAction->setObjectName("Stop Service");
	fileStopServiceAction->setIconText(tr("Stop Service"));
	fileMenu->insertAction(actionWPS, fileStopServiceAction);

	fileStartServiceAction = new QAction(this);
	fileStartServiceAction->setObjectName("Start Service");
	fileStartServiceAction->setIconText(tr("Start Service"));
	fileMenu->insertAction(fileStopServiceAction, fileStartServiceAction);

	connect(fileStartServiceAction, SIGNAL(triggered())
	      , this, SLOT(startService()));
	connect(fileStopServiceAction, SIGNAL(triggered())
	      , this, SLOT(stopService()));

	addInterfaceAction = new QAction(this);
	addInterfaceAction->setIconText(tr("Add Interface"));
	fileMenu->insertAction(fileStartServiceAction, addInterfaceAction);

	connect(addInterfaceAction, SIGNAL(triggered())
	      , this, SLOT(addInterface()));

	add_iface = NULL;
#endif /* CONFIG_NATIVE_WINDOWS */

	(void) statusBar();

	/*
	 * Disable WPS tab by default; it will be enabled if wpa_supplicant is
	 * built with WPS support.
	 */
	wpsTab->setEnabled(false);
	wpaguiTab->setTabEnabled(wpaguiTab->indexOf(wpsTab), false);

	connect(disconReconAction, SIGNAL(triggered())
	      , this, SLOT(disconnReconnect()));
	connect(eventHistoryAction, SIGNAL(triggered())
	      , this, SLOT(eventHistory()));
	connect(scanAction, SIGNAL(triggered())
	      , this, SLOT(scan()));
	connect(saveConfigAction, SIGNAL(triggered())
	      , this, SLOT(saveConfig()));
	connect(wpsAction, SIGNAL(triggered())
	      , this, SLOT(wpsDialog()));
	connect(peersAction, SIGNAL(triggered())
	      , this, SLOT(peersDialog()));
	connect(quitAction, SIGNAL(triggered())
	      , qApp, SLOT(quit()));

	connect(networkAddAction, SIGNAL(triggered())
	      , this, SLOT(addNetwork()));
	connect(networkEditAction, SIGNAL(triggered())
	      , this, SLOT(editListedNetwork()));
	connect(networkDisEnableAction, SIGNAL(triggered())
	      , this, SLOT(disEnableNetwork()));
	connect(networkEnableAllAction, SIGNAL(triggered())
	      , this, SLOT(enableAllNetworks()));
	connect(networkDisableAllAction, SIGNAL(triggered())
	      , this, SLOT(disableAllNetworks()));
	connect(networkRemoveAction, SIGNAL(triggered())
	      , this, SLOT(removeListedNetwork()));
	connect(networkRemoveAllAction, SIGNAL(triggered())
	      , this, SLOT(removeAllNetworks()));

	connect(helpIndexAction, SIGNAL(triggered())
	      , this, SLOT(helpIndex()));
	connect(helpContentsAction, SIGNAL(triggered())
	      , this, SLOT(helpContents()));
	connect(helpAboutAction, SIGNAL(triggered())
	      , this, SLOT(helpAbout()));
	connect(helpAboutQtAction, &QAction::triggered
	      , qApp, &QApplication::aboutQt);

	connect(adapterSelect, SIGNAL(activated(const QString&))
	      , this, SLOT(selectAdapter(const QString&)));

	connect(networkList, SIGNAL(itemSelectionChanged())
	      , this, SLOT(networkSelectionChanged()));
	connect(networkList, SIGNAL(itemDoubleClicked(QTreeWidgetItem *, int))
	      , this, SLOT(editListedNetwork()));

	connect(eventList, SIGNAL(itemDoubleClicked(QTreeWidgetItem *, int))
	      , eventList, SLOT(scrollToBottom()));

	connect(wpaguiTab, SIGNAL(currentChanged(int))
	      , this, SLOT(tabChanged(int)));
	connect(wpsPbcButton, SIGNAL(clicked())
	      , this, SLOT(wpsPbc()));
	connect(wpsPinButton, SIGNAL(clicked())
	      , this, SLOT(wpsGeneratePin()));
	connect(wpsApPinEdit, SIGNAL(textChanged(const QString &))
	      , this, SLOT(wpsApPinChanged(const QString &)));
	connect(wpsApPinButton, SIGNAL(clicked())
	      , this, SLOT(wpsApPin()));

	eh = NULL;
	scanres = NULL;
	peers = NULL;
	udr = NULL;
	tray_icon = NULL;
	ctrl_iface = NULL;
	ctrl_conn = NULL;
	monitor_conn = NULL;
	msgNotifier = NULL;
	ctrl_iface_dir = strdup("/var/run/wpa_supplicant");
	signalMeterInterval = 0;

	parse_argv();

	connect(disableNotifierAction, SIGNAL(toggled(bool))
	      , this, SLOT(disableNotifier(bool)));
	connect(enablePollingAction, SIGNAL(toggled(bool))
	      , this, SLOT(enablePolling(bool)));

#ifndef QT_NO_SESSIONMANAGER
	if (app->isSessionRestored()) {
		QSettings settings("wpa_supplicant", "wpa_gui");
		settings.beginGroup("state");
		if (app->sessionId()
		   .compare(settings.value("session_id").toString()) == 0 &&
		              settings.value("in_tray").toBool())
			tally.insert(StartInTray);

		settings.endGroup();
	}
#endif

	watchdogTimer = new QTimer(this);
	connect(watchdogTimer, SIGNAL(timeout()), SLOT(ping()));
	watchdogTimer->setSingleShot(false);
	letTheDogOut(PomDog, enablePollingAction->isChecked());

	signalMeterTimer = new QTimer(this);
	signalMeterTimer->setInterval(signalMeterInterval);
	connect(signalMeterTimer, SIGNAL(timeout()), SLOT(signalMeterUpdate()));

	// Must done after creation of watchdogTimer due to showEvent catch
	if (QSystemTrayIcon::isSystemTrayAvailable())
		createTrayIcon(tally.contains(StartInTray));
	else
		show();

	setState(WpaUnknown);

	ping();
}


WpaGui::~WpaGui()
{
	delete msgNotifier;

	if (monitor_conn) {
		wpa_ctrl_detach(monitor_conn);
		wpa_ctrl_close(monitor_conn);
		monitor_conn = NULL;
	}
	if (ctrl_conn) {
		wpa_ctrl_close(ctrl_conn);
		ctrl_conn = NULL;
	}

	if (eh) {
		eh->close();
		delete eh;
		eh = NULL;
	}

	if (scanres) {
		scanres->close();
		delete scanres;
		scanres = NULL;
	}

	if (peers) {
		peers->close();
		delete peers;
		peers = NULL;
	}

#ifdef CONFIG_NATIVE_WINDOWS
	if (add_iface) {
		add_iface->close();
		delete add_iface;
		add_iface = NULL;
	}
#endif /* CONFIG_NATIVE_WINDOWS */

	if (udr) {
		udr->close();
		delete udr;
		udr = NULL;
	}

	free(ctrl_iface);
	ctrl_iface = NULL;

	free(ctrl_iface_dir);
	ctrl_iface_dir = NULL;
}


void WpaGui::languageChange()
{
	retranslateUi(this);
}


void WpaGui::parse_argv()
{
	int c;
	bool hasN(false), hasP(false);
	WpaGuiApp *app = qobject_cast<WpaGuiApp*>(qApp);
	for (;;) {
		c = getopt(app->argc, app->argv, "i:m:p:tqNP");
		if (c < 0)
			break;
		switch (c) {
		case 'i':
			free(ctrl_iface);
			ctrl_iface = strdup(optarg);
			adapterSelect->clear();
			adapterSelect->addItem(ctrl_iface);
			adapterSelect->setCurrentIndex(0);
			break;
		case 'm':
			signalMeterInterval = atoi(optarg) * 1000;
			break;
		case 'p':
			free(ctrl_iface_dir);
			ctrl_iface_dir = strdup(optarg);
			break;
		case 't':
			tally.insert(StartInTray);
			break;
		case 'q':
			tally.insert(QuietMode);
			break;
		case 'N':
			hasN = true;
			break;
		case 'P':
			hasP = true;
			break;
		}
	}

	if(hasN) {
		if (disableNotifierAction->isEnabled()) {
			disableNotifierAction->setChecked(true);
			enablePollingAction->setChecked(true);
			enablePollingAction->setEnabled(false);
			logHint("QSocketNotifier disabled by command line option -N");
		}
	} else if(hasP) {
		if (enablePollingAction->isEnabled()) {
			enablePollingAction->setChecked(true);
			logHint("Polling enabled by command line -P");
		}
	}
}


int WpaGui::openCtrlConnection(const char *ifname)
{
	char *cfile;
	int flen;
	char buf[2048], *pos, *pos2;
	size_t len;

	if (ifname) {
		if (ifname != ctrl_iface) {
			free(ctrl_iface);
			ctrl_iface = strdup(ifname);
		}
	} else {
		adapterSelect->clear();
		adapterSelect->addItem(tr("Not specified"));
		adapterSelect->setCurrentIndex(0);
#ifdef CONFIG_CTRL_IFACE_UDP
		free(ctrl_iface);
		ctrl_iface = strdup("udp");
#endif /* CONFIG_CTRL_IFACE_UDP */
#ifdef CONFIG_CTRL_IFACE_UNIX
		struct dirent *dent;
		DIR *dir = opendir(ctrl_iface_dir);
		free(ctrl_iface);
		ctrl_iface = NULL;
		if (dir) {
			while ((dent = readdir(dir))) {
#ifdef _DIRENT_HAVE_D_TYPE
				/* Skip the file if it is not a socket.
				 * Also accept DT_UNKNOWN (0) in case
				 * the C library or underlying file
				 * system does not support d_type. */
				if (dent->d_type != DT_SOCK &&
				    dent->d_type != DT_UNKNOWN)
					continue;
#endif /* _DIRENT_HAVE_D_TYPE */

				if (strcmp(dent->d_name, ".") == 0 ||
				    strcmp(dent->d_name, "..") == 0)
					continue;
				debug("Selected interface '%s'",
				      dent->d_name);
				ctrl_iface = strdup(dent->d_name);
				break;
			}
			closedir(dir);
		}
#endif /* CONFIG_CTRL_IFACE_UNIX */
#ifdef CONFIG_CTRL_IFACE_NAMED_PIPE
		struct wpa_ctrl *ctrl;
		int ret;

		free(ctrl_iface);
		ctrl_iface = NULL;

		ctrl = wpa_ctrl_open(NULL);
		if (ctrl) {
			len = sizeof(buf) - 1;
			ret = wpa_ctrl_request(ctrl, "INTERFACES", 10, buf,
					       &len, NULL);
			if (ret >= 0) {
				tally.insert(connectedToService);
				buf[len] = '\0';
				pos = strchr(buf, '\n');
				if (pos)
					*pos = '\0';
				ctrl_iface = strdup(buf);
			}
			wpa_ctrl_close(ctrl);
		}
#endif /* CONFIG_CTRL_IFACE_NAMED_PIPE */
	}

	try
	{
	if (ctrl_iface == NULL) {
#ifdef CONFIG_NATIVE_WINDOWS
		static bool first = true;
		if (first && !serviceRunning()) {
			first = false;
			if (QMessageBox::warning(
				    this, qAppName(),
				    tr("wpa_supplicant service is not "
				       "running.\n"
				       "Do you want to start it?"),
				    QMessageBox::Yes | QMessageBox::No) ==
			    QMessageBox::Yes)
				startService();
		}
#endif /* CONFIG_NATIVE_WINDOWS */
		throw 1;
	}

#ifdef CONFIG_CTRL_IFACE_UNIX
	flen = strlen(ctrl_iface_dir) + strlen(ctrl_iface) + 2;
	cfile = (char *) malloc(flen);
	if (cfile == NULL)
		throw 2;
	snprintf(cfile, flen, "%s/%s", ctrl_iface_dir, ctrl_iface);
#else /* CONFIG_CTRL_IFACE_UNIX */
	flen = strlen(ctrl_iface) + 1;
	cfile = (char *) malloc(flen);
	if (cfile == NULL)
		throw 2;
	snprintf(cfile, flen, "%s", ctrl_iface);
#endif /* CONFIG_CTRL_IFACE_UNIX */

	if (ctrl_conn) {
		wpa_ctrl_close(ctrl_conn);
		ctrl_conn = NULL;
	}

	if (monitor_conn) {
		delete msgNotifier;
		msgNotifier = NULL;
		wpa_ctrl_detach(monitor_conn);
		wpa_ctrl_close(monitor_conn);
		monitor_conn = NULL;
	}

	logHint(tr("Connection to wpa_supplicant..."));

	ctrl_conn = wpa_ctrl_open(cfile);
	if (ctrl_conn == NULL) {
		free(cfile);
		throw 3;
	}

	logHint(tr("...successful! Using interface %1").arg(ctrl_iface));

	monitor_conn = wpa_ctrl_open(cfile);
	free(cfile);
	if (monitor_conn == NULL) {
		wpa_ctrl_close(ctrl_conn);
		ctrl_conn = NULL;
		throw 4;
	}
	if (wpa_ctrl_attach(monitor_conn)) {
		wpa_ctrl_close(monitor_conn);
		monitor_conn = NULL;
		wpa_ctrl_close(ctrl_conn);
		ctrl_conn = NULL;
		throw 5;
	}
	}
	catch (int e)
	{
		QString errTxt(tr("Fatal error: "));
		QString dbgTxt;
		WpaStateType oldState = wpaState;

		switch (e) {
			case 1:
				dbgTxt = "Failed to open control connection to wpa_supplicant.";
				errTxt = tr("No running wpa_supplicant found");
				setState(WpaNotRunning);
				break;
			case 2:
				dbgTxt = "Malloc of cfile fails";
				errTxt.append(dbgTxt);
				setState(WpaFatal);
				break;
			case 3:
				dbgTxt = "Failed to open control connection to wpa_supplicant on adapter ";
				dbgTxt.append(ctrl_iface);
				errTxt = tr("No wpa_supplicant with adapter '%1' found").arg(ctrl_iface);
				setState(WpaNotRunning);
				break;
			case 4:
				dbgTxt = "monitor_conn == NULL";
				errTxt.append(dbgTxt);
				setState(WpaFatal);
				break;
			case 5:
				dbgTxt = "Failed to attach to wpa_supplicant";
				errTxt.append(dbgTxt);
				setState(WpaFatal);
				break;
		}

		if (oldState != wpaState ) {
			if (adapterSelect->count() < 2)
				adapterSelect->setEnabled(false);
			logHint(tr("...Failed!"));
			logHint(errTxt);
			if (WpaFatal != wpaState)
				logHint(tr("Wait for wpa_supplicant..."));
		}

		debug("case %d : %s",e, dbgTxt.toLocal8Bit().constData());
		return -1;
	}

	if (disableNotifierAction->isChecked()) {
		logHint("Use polling to fetch news from wpa_supplicant");
	} else {
		msgNotifier = new QSocketNotifier(wpa_ctrl_get_fd(monitor_conn),
		                                  QSocketNotifier::Read, this);
		connect(msgNotifier, SIGNAL(activated(int)), SLOT(receiveMsgs()));
	}

	adapterSelect->clear();
	adapterSelect->addItem(ctrl_iface);
	adapterSelect->setCurrentIndex(0);

	len = sizeof(buf) - 1;
	if (wpa_ctrl_request(ctrl_conn, "INTERFACES", 10, buf, &len, NULL) >=
	    0) {
		buf[len] = '\0';
		pos = buf;
		while (*pos) {
			pos2 = strchr(pos, '\n');
			if (pos2)
				*pos2 = '\0';
			if (strcmp(pos, ctrl_iface) != 0)
				adapterSelect->addItem(pos);
			if (pos2)
				pos = pos2 + 1;
			else
				break;
		}
	}

	len = sizeof(buf) - 1;
	if (wpa_ctrl_request(ctrl_conn, "GET_CAPABILITY eap", 18, buf, &len,
			     NULL) >= 0) {
		buf[len] = '\0';

		QString res(buf);
		QStringList types = res.split(QChar(' '));
		bool wps = types.contains("WSC");
		wpsAction->setEnabled(wps);
		wpsTab->setEnabled(wps);
		wpaguiTab->setTabEnabled(wpaguiTab->indexOf(wpsTab), wps);
	}

	setState(WpaRunning);
	return 0;
}


int WpaGui::ctrlRequest(const char *cmd, char *buf, size_t *buflen)
{
	int ret;

	if (ctrl_conn == NULL)
		return -3;
	ret = wpa_ctrl_request(ctrl_conn, cmd, strlen(cmd), buf, buflen, NULL);
	if (ret == -2)
		debug("'%s' command timed out.", cmd);
	else if (ret < 0)
		debug("'%s' command failed.", cmd);

	return ret;
}


void WpaGui::wpaStateTranslate(const char *state)
{
	if (!strcmp(state, "DISCONNECTED")) {
		setState(WpaDisconnected);
	}
	else if (!strcmp(state, "INACTIVE")) {
		setState(WpaInactive);
	}
	else if (!strcmp(state, "SCANNING")) {
		setState(WpaScanning);
	}
	else if (!strcmp(state, "AUTHENTICATING")) {
		setState(WpaAuthenticating);
	}
	else if (!strcmp(state, "ASSOCIATING")) {
		setState(WpaAssociating);
	}
	else if (!strcmp(state, "ASSOCIATED")) {
		setState(WpaAssociated);
	}
	else if (!strcmp(state, "4WAY_HANDSHAKE")) {
		setState(Wpa4WayHandshake);
	}
	else if (!strcmp(state, "GROUP_HANDSHAKE")) {
		setState(WpaGroupHandshake);
	}
	else if (!strcmp(state, "COMPLETED")) {
		setState(WpaCompleted);
	}
	else if (!strcmp(state, "NOT_RUNNING")) {
		setState(WpaNotRunning);
	}
	else {
		setState(WpaUnknown);
	}
}


void WpaGui::setState(const WpaStateType state)
{
	static int oldState = -1;
	TrayIconType icon   = TrayIconNone;
	QString stateText;

	const QString DiscActTxt(tr("Disconnect"));
	const QString DiscActTTTxt(tr("Disable WLAN networking"));
	const QString RecActTxt(tr("Reconnect"));
	const QString RecActTTTxt(tr("Enable WLAN networking"));

	if (state == oldState)
		return;

	oldState = state;
	tally.insert(StatusNeedsUpdate);

	switch (state) {
		case WpaFatal:
			wpaState = WpaFatal;
			icon = TrayIconError;
			stateText = tr("Fatal Error!");
			disconReconAction->setEnabled(false);
			wpsAction->setEnabled(false);
			saveConfigAction->setEnabled(false);
			networkMenu->setEnabled(false);
			wpaguiTab->setTabEnabled(wpaguiTab->indexOf(networksTab), false);
			wpaguiTab->setTabEnabled(wpaguiTab->indexOf(wpsTab), false);
			wpaguiTab->setCurrentWidget(eventTab);
			break;
		case WpaUnknown:
			wpaState = WpaUnknown;
// 			icon = ;
			stateText = tr("Unknown");
			rssiBar->hide();
			break;
		case WpaNotRunning:
			wpaState = WpaNotRunning;
			icon = TrayIconError;
			stateText = tr("No running wpa_supplicant");
			stopWpsRun(true);
			disconReconAction->setEnabled(false);
			wpsAction->setEnabled(false);
			saveConfigAction->setEnabled(false);
			networkMenu->setEnabled(false);
			wpaguiTab->setTabEnabled(wpaguiTab->indexOf(networksTab), false);
			wpaguiTab->setTabEnabled(wpaguiTab->indexOf(wpsTab), false);
			wpaguiTab->setCurrentWidget(eventTab);
			// FIXME is it possible that wpa_supplicant runs with one adapter
			// but not the other? If not set to false here and remove the
			// line in openCtrlConnection()
			// adapterSelect->setEnabled(false);
			tally.insert(NetworkNeedsUpdate);
			if (ctrl_conn) {
				wpa_ctrl_close(ctrl_conn);
				ctrl_conn = NULL;
			}
			break;
		case WpaRunning:
			wpaState = WpaRunning;
			icon = TrayIconSignalNone;
			stateText = tr("wpa_supplicant is running");
			disconReconAction->setEnabled(true);
			wpsAction->setEnabled(true);
			saveConfigAction->setEnabled(true);
			networkMenu->setEnabled(true);
			adapterSelect->setEnabled(true);
			wpaguiTab->setTabEnabled(wpaguiTab->indexOf(networksTab), true);
			break;
		case WpaAuthenticating:
			wpaState = WpaAuthenticating;
			stateText = tr("Authenticating");
			icon = TrayIconAcquiring;
			break;
		case WpaAssociating:
			wpaState = WpaAssociating;
			stateText = tr("Associating");
			icon = TrayIconAcquiring;
			break;
		case WpaAssociated:
			wpaState = WpaAssociated;
			stateText = tr("Associated");
			icon = TrayIconAcquiring;
			break;
		case Wpa4WayHandshake:
			wpaState = Wpa4WayHandshake;
			stateText = tr("4-Way Handshake");
			icon = TrayIconAcquiring;
			break;
		case WpaGroupHandshake:
			wpaState = WpaGroupHandshake;
			stateText = tr("Group Handshake");
			icon = TrayIconAcquiring;
			break;
		case WpaWait4Registrar:
			stateText = tr("Wait for registrar");
			icon = TrayIconAcquiring;
			break;
		case WpaInactive:
			wpaState = WpaInactive;
			icon = TrayIconInactive;
			stateText = tr("Inactive");
			disconReconAction->setText(DiscActTxt);
			disconReconAction->setToolTip(DiscActTTTxt);
			disconReconAction->setEnabled(true);
			break;
		case WpaScanning:
			wpaState = WpaScanning;
			icon = TrayIconScanning;
			stateText = tr("Scanning");
			disconReconAction->setText(DiscActTxt);
			disconReconAction->setToolTip(DiscActTTTxt);
			disconReconAction->setEnabled(true);
			break;
		case WpaDisconnected:
			wpaState = WpaDisconnected;
			icon = TrayIconOffline;
			stateText = tr("Disconnected");
			disconReconAction->setText(RecActTxt);
			disconReconAction->setToolTip(RecActTTTxt);
			disconReconAction->setEnabled(true);
			tally.insert(NetworkNeedsUpdate);
			rssiBar->hide();
			break;
		case WpaLostSignal:
			wpaState = WpaLostSignal;
			icon = TrayIconSignalNone;
			stateText = tr("Lost signal");
			rssiBar->hide();
			break;
		case WpaCompleted:
			wpaState = WpaCompleted;
			icon = TrayIconSignalExcellent;
			stateText = tr("Connected");
			stopWpsRun(true);
			signalMeterTimer->start();
			disconReconAction->setText(DiscActTxt);
			disconReconAction->setToolTip(DiscActTTTxt);
			disconReconAction->setEnabled(true);
			tally.insert(NetworkNeedsUpdate);
			rssiBar->show();
			break;
	}

	debug("#### New state: %s", stateText.toLocal8Bit().constData());

	textStatus->setText(stateText);
	updateTrayToolTip(stateText);
	updateTrayIcon(icon);
}


void WpaGui::updateStatus(bool changed/* = true*/)
{
	char buf[2048], *start, *end, *pos;
	size_t len(sizeof(buf) - 1);

	debug(" updateStatus ??");

	if (!changed)
		return;

	debug(" updateStatus >>");
	tally.remove(StatusNeedsUpdate);

	// Wake the dog after network reconnect
	if (!watchdogTimer->isActive() && enablePollingAction->isChecked())
		letTheDogOut(PomDog);

	textAuthentication->clear();
	textEncryption->clear();
	textSsid->clear();
	textBssid->clear();
	textIpAddress->clear();

	if (WpaNotRunning == wpaState) {
		letTheDogOut(BorderCollie);
		return;
	}
	debug(" updateStatus >>>>");

	if (ctrlRequest("STATUS", buf, &len) < 0) {
		logHint(tr("Could not get status from wpa_supplicant"));
		updateTrayToolTip(tr("No status information"));
#ifndef CONFIG_NATIVE_WINDOWS
		setState(WpaUnknown);
		ctrl_conn = NULL;
#endif /* CONFIG_NATIVE_WINDOWS */

#ifdef CONFIG_NATIVE_WINDOWS
		static bool first = true;
		if (first && connectedToService &&
		    (ctrl_iface == NULL || *ctrl_iface == '\0')) {
			first = false;
			if (QMessageBox::information(
				    this, qAppName(),
				    tr("No network interfaces in use.\n"
				       "Would you like to add one?"),
				    QMessageBox::Yes | QMessageBox::No) ==
			    QMessageBox::Yes)
				addInterface();
		}
#endif /* CONFIG_NATIVE_WINDOWS */
		return;
	}
	debug(" updateStatus >>>>>>");

	buf[len] = '\0';

	char *pairwise_cipher = NULL, *group_cipher = NULL;
	char *mode = NULL;

	start = buf;
	while (*start) {
		bool last = false;
		end = strchr(start, '\n');
		if (end == NULL) {
			last = true;
			end = start;
			while (end[0] && end[1])
				end++;
		}
		*end = '\0';

		pos = strchr(start, '=');
		if (pos) {
			*pos++ = '\0';
			if (strcmp(start, "bssid") == 0) {
				textBssid->setText(pos);
			} else if (strcmp(start, "ssid") == 0) {
				textSsid->setText(pos);
				// Needed to fix rare cases with a missig ssid in tool tip
				updateTrayToolTip(pos);
			} else if (strcmp(start, "ip_address") == 0) {
				textIpAddress->setText(pos);
			} else if (strcmp(start, "wpa_state") == 0) {
				wpaStateTranslate(pos);
			} else if (strcmp(start, "key_mgmt") == 0) {
				textAuthentication->setText(pos);
				/* TODO: could add EAP status to this */
			} else if (strcmp(start, "pairwise_cipher") == 0) {
				pairwise_cipher = pos;
			} else if (strcmp(start, "group_cipher") == 0) {
				group_cipher = pos;
			} else if (strcmp(start, "mode") == 0) {
				mode = pos;
			}
		}

		if (last)
			break;

		start = end + 1;
	}

	if (mode && !textStatus->text().contains(mode))
		textStatus->setText(textStatus->text() + " (" + mode + ")");

	if (pairwise_cipher || group_cipher) {
		QString encr;
		if (pairwise_cipher && group_cipher &&
		    strcmp(pairwise_cipher, group_cipher) != 0) {
			encr.append(pairwise_cipher);
			encr.append(" + ");
			encr.append(group_cipher);
		} else if (pairwise_cipher) {
			encr.append(pairwise_cipher);
		} else {
			encr.append(group_cipher);
			encr.append(" [group key only]");
		}
		textEncryption->setText(encr);
	} else
		textEncryption->clear();

	logHint(textStatus->text());

	if (!signalMeterInterval)
		signalMeterUpdate();

	tally.remove(StatusNeedsUpdate);
	debug(" updateStatus <<<<<<");
}


void WpaGui::updateNetworks(bool changed/* = true*/)
{
	char buf[4096], *start, *end, *id, *ssid, *bssid, *flags;
	size_t len;
	int was_selected = -1;

	debug(" updateNetworks() ??");

	if (!changed)
		return;

	tally.remove(NetworkNeedsUpdate);
	QTreeWidgetItem *currentNetwork = NULL;
	QTreeWidgetItem *selectedNetwork = networkList->currentItem();

	if (selectedNetwork)
		was_selected = selectedNetwork->text(0).toInt();

	selectedNetwork = NULL;

	const QSignalBlocker blocker(networkList);
	networkList->clear();

	if (ctrl_conn == NULL)
		return;

	debug(" updateNetworks() >>");
	len = sizeof(buf) - 1;
	if (ctrlRequest("LIST_NETWORKS", buf, &len) < 0)
		return;

	debug(" updateNetworks() >>>>");
	buf[len] = '\0';
	start = strchr(buf, '\n');
	if (start == NULL)
		return;
	start++;

	debug(" updateNetworks() >>>>>>");

	while (*start) {
		bool last = false;
		end = strchr(start, '\n');
		if (end == NULL) {
			last = true;
			end = start;
			while (end[0] && end[1])
				end++;
		}
		*end = '\0';

		id = start;
		ssid = strchr(id, '\t');
		if (ssid == NULL)
			break;
		*ssid++ = '\0';
		bssid = strchr(ssid, '\t');
		if (bssid == NULL)
			break;
		*bssid++ = '\0';
		flags = strchr(bssid, '\t');
		if (flags == NULL)
			break;
		*flags++ = '\0';

		if (strstr(flags, "[DISABLED][P2P-PERSISTENT]")) {
			if (last)
				break;
			start = end + 1;
			continue;
		}

		QTreeWidgetItem *item = new QTreeWidgetItem(networkList);
		item->setText(0, id);
		item->setText(1, ssid);
		item->setText(2, bssid);
		item->setText(3, flags);

		if (strstr(flags, "[CURRENT]")) {
			currentNetwork = item;
		}
		if (atoi(id) == was_selected) {
			networkList->setCurrentItem(item);
			selectedNetwork = item;
			debug(" restore old selection: %d", was_selected);
		}

		if (last)
			break;
		start = end + 1;
	}

	if (!selectedNetwork) {
		if (currentNetwork) {
			networkList->setCurrentItem(currentNetwork);
			selectedNetwork = currentNetwork;
			debug("select current network");
		} else {
			networkList->setCurrentItem(NULL);
			debug("select NULL");
		}
	}

	if (selectedNetwork)
		networkList->scrollToItem(selectedNetwork);

	for (int i = 0; i < networkList->columnCount(); ++i)
		networkList->resizeColumnToContents(i);

	if (networkList->topLevelItemCount()) {
		networkEnableAllAction->setEnabled(true);
		networkDisableAllAction->setEnabled(true);
		networkRemoveAllAction->setEnabled(true);
	}
	else {
		networkEnableAllAction->setEnabled(false);
		networkDisableAllAction->setEnabled(false);
		networkRemoveAllAction->setEnabled(false);
	}

	networkSelectionChanged();

	debug("updateNetworks() <<<<<<");
}


void WpaGui::disableNotifier(bool yes)
{
	if (yes)
		logHint("User requests to disable QSocketNotifier");
	else
		logHint("User requests to enable QSocketNotifier");

	// So much effort only to block the log hint
	const QSignalBlocker blocker(enablePollingAction);
	enablePollingAction->setChecked(yes);
	enablePollingAction->setEnabled(!yes);
	letTheDogOut(PomDog, yes);

	openCtrlConnection(ctrl_iface);
}


void WpaGui::letTheDogOut(int dog, bool yes)
{
	if (yes && dog >= PomDog) {
		if (watchdogTimer->interval() != dog)
			debug("New dog on patrol %d", dog);
		watchdogTimer->start(dog);
	}
	else if (watchdogTimer->isActive()) {
		watchdogTimer->stop();
		debug("No dog on patrol");
	}
}


void WpaGui::letTheDogOut(int dog/* = PomDog*/)
{
	letTheDogOut(dog, true);
}


void WpaGui::letTheDogOut(bool yes/* = true*/)
{
	letTheDogOut(watchdogTimer->interval(), yes);
}


void WpaGui::enablePolling(bool yes)
{
	if (yes)
		logHint("User requests to enable polling");
	else
		logHint("User requests to disable polling");

	letTheDogOut(PomDog, yes);
}


void WpaGui::helpIndex()
{
	debug("helpIndex");
}


void WpaGui::helpContents()
{
	debug("helpContents");
}


void WpaGui::helpAbout()
{
	QMessageBox::about(this, "wpa_gui for wpa_supplicant",
			   "Copyright (c) 2003-2015,\n"
			   "Jouni Malinen <j@w1.fi>\n"
			   "and contributors.\n"
			   "\n"
			   "This software may be distributed under\n"
			   "the terms of the BSD license.\n"
			   "See README for more details.\n"
			   "\n"
			   "This product includes software developed\n"
			   "by the OpenSSL Project for use in the\n"
			   "OpenSSL Toolkit (http://www.openssl.org/)\n");
}


void WpaGui::disconnReconnect()
{
	char reply[10];
	size_t reply_len = sizeof(reply);

	disconReconAction->setEnabled(false);

	if (WpaDisconnected == wpaState) {
		logHint("User requests network reconnect");
		ctrlRequest("REASSOCIATE", reply, &reply_len);
	} else if (WpaCompleted == wpaState || WpaScanning  == wpaState ||
		       WpaInactive == wpaState)
	{
		logHint("User requests network disconnect");
		ctrlRequest("DISCONNECT", reply, &reply_len);
		stopWpsRun(false);
	}

	updateStatus();
}


void WpaGui::scan()
{
	if (scanres) {
		scanres->close();
		delete scanres;
	}

	scanres = new ScanResults();
	if (scanres == NULL)
		return;
	scanres->setWpaGui(this);
	scanres->show();
	scanres->activateWindow();
	scanres->exec();
}


void WpaGui::eventHistory()
{
	if (eh) {
		eh->close();
		delete eh;
	}

	eh = new EventHistory();
	if (eh == NULL)
		return;
	eh->addEvents(msgs);
	eh->show();
	eh->activateWindow();
	eh->exec();
}


void WpaGui::ping()
{
	char  buf[10];
	size_t len(sizeof(buf) - 1);
	static WpaStateType oldState(WpaUnknown);

	debug("PING! >>>>> state: %d / %d",oldState, wpaState);
	if (wpaState > WpaNotRunning)
		receiveMsgs();
	debug("PING! ----- state: %d / %d",oldState, wpaState);

	bool stateChanged(wpaState != oldState);
	oldState = wpaState;

	if (scanres && !scanres->isVisible()) {
		delete scanres;
		scanres = NULL;
	}

	if (eh && !eh->isVisible()) {
		delete eh;
		eh = NULL;
	}

	if (udr && !udr->isVisible()) {
		delete udr;
		udr = NULL;
	}

	int dog(watchdogTimer->interval());
	int maxDog(SnoozingDog);

	if (stateChanged)
		dog = PomDog;
	else {
		if (BassetHound < dog)
			dog += BassetHound;
		else if (BorderCollie < dog)
			dog += BorderCollie;
		else
			dog += PomDog;
	}

	switch (wpaState) {
		case WpaFatal:
			letTheDogOut(false);
			signalMeterTimer->stop();
			logHint(tr("Polling halted"));
			debug("PING! <-<<<");
			return;
			break;
		case WpaDisconnected:
// 			maxDog = SnoozingDog;
			break;
		case WpaInactive:
		case WpaScanning:
			maxDog = BassetHound;
			break;
		case WpaUnknown:
		case WpaNotRunning:
			if (openCtrlConnection(ctrl_iface) == 0) {
				updateStatus();
				updateNetworks();
				letTheDogOut(enablePollingAction->isChecked());
				debug("PING! <<<-<");
				return;
			}
			maxDog = BassetHound;
			break;
		case WpaAssociated:
		case WpaCompleted:
			if (ctrlRequest("PING", buf, &len) < 0) {
				logHint(tr("PING failed - trying to reconnect"));
				dog = PomDog;
				setState(WpaUnknown);
			} else {
				debug("Play ping-pong");
				updateStatus();
				if (isVisible())
					updateNetworks();
			}
			break;
		default :
			debug("wpaState ignored by PING: %d", wpaState);
			break;
	}

	if (isVisible())
		maxDog = BorderCollie;

	if (dog > maxDog)
		dog = maxDog;

	letTheDogOut(dog);

	if (stateChanged)
		updateStatus();

	debug("PING! <<<<<");
}


void WpaGui::signalMeterUpdate()
{
	char reply[128];
	size_t reply_len = sizeof(reply);
	char *rssi;
	int rssi_value;

	if (WpaCompleted != wpaState)
		return;

	ctrlRequest("SIGNAL_POLL", reply, &reply_len);

	/* In order to eliminate signal strength fluctuations, try
	 * to obtain averaged RSSI value in the first place. */
	if ((rssi = strstr(reply, "AVG_RSSI=")) != NULL)
		rssi_value = atoi(&rssi[sizeof("AVG_RSSI")]);
	else if ((rssi = strstr(reply, "RSSI=")) != NULL)
		rssi_value = atoi(&rssi[sizeof("RSSI")]);
	else {
		logHint(tr("Failed to get RSSI value"));
		updateTrayIcon(TrayIconSignalNone);
		return;
	}

	debug("RSSI value: %d", rssi_value);
	rssiBar->setValue(rssi_value);

	/*
	 * NOTE: The code below assumes, that the unit of the value returned
	 * by the SIGNAL POLL request is dBm. It might not be true for all
	 * wpa_supplicant drivers.
	 */

	/*
	 * Calibration is based on "various Internet sources". Nonetheless,
	 * it seems to be compatible with the Windows 8.1 strength meter -
	 * tested on Intel Centrino Advanced-N 6235.
	 */
	if (rssi_value >= -60)
		updateTrayIcon(TrayIconSignalExcellent);
	else if (rssi_value >= -68)
		updateTrayIcon(TrayIconSignalGood);
	else if (rssi_value >= -76)
		updateTrayIcon(TrayIconSignalOk);
	else if (rssi_value >= -84)
		updateTrayIcon(TrayIconSignalWeak);
	else
		updateTrayIcon(TrayIconSignalNone);

	if (!signalMeterInterval)
		signalMeterTimer->stop();
}


void WpaGui::logHint(const QString &hint) {

	QString text(hint);
	static QString lastHint;

	if (hint == lastHint)
		return;

	lastHint = hint;

	while (text.endsWith('\n'))
		text.chop(1);

	debug("UserHint: %s", hint.toLocal8Bit().constData());

	if (text.count('\n') == 0)
		statusHint->setText(text);

	bool scroll = true;
	if (eventList->verticalScrollBar()->value() <
	    eventList->verticalScrollBar()->maximum())
		scroll = false;

	QString now = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
	now.chop(1);

	QTreeWidgetItem *item = new QTreeWidgetItem(eventList);
	item->setText(0, now);
	item->setText(1, text);


	if (scroll)
		eventList->scrollToBottom();
}


static int str_match(const char *a, const char *b)
{
	return strncmp(a, b, strlen(b)) == 0;
}


void WpaGui::processMsg(char *msg)
{
	char *pos = msg;
	int priority = 2;

	if (*pos == '<') {
		/* skip priority */
		pos++;
		priority = atoi(pos);
		pos = strchr(pos, '>');
		if (pos)
			pos++;
		else
			pos = msg;
	}

	WpaMsg wm(pos, priority);
	if (eh)
		eh->addEvent(wm);
	if (peers)
		peers->event_notify(wm);
	msgs.append(wm);
	while (msgs.count() > 100)
		msgs.pop_front();

	debug("processMsg - %s", msg);

	if (str_match(pos, WPA_CTRL_REQ)) {
		processCtrlReq(pos + strlen(WPA_CTRL_REQ));
	} else if (str_match(pos, WPA_EVENT_SCAN_STARTED)) {
		setState(WpaScanning);
	} else if (str_match(pos, WPA_EVENT_SCAN_RESULTS) && scanres) {
		logHint(tr("Scan results available"));
		scanres->updateResults();
	} else if (str_match(pos, WPA_EVENT_NETWORK_NOT_FOUND)) {
		logHint("Network not found");
		tally.insert(NetworkNeedsUpdate);
	} else if (str_match(pos, WPA_EVENT_DISCONNECTED)) {
		if (strstr(pos, "reason=3")) {
			showTrayMessage(tr("Disconnected from network"));
			if (WpaDisconnected != wpaState) {
				// Unclear situation, possible supplicant shut down where
				// any ctrlRequest() would fail, So ensure not to update
				// status or network until some clarifying message, see below.
				setState(WpaUnknown);
				tally.remove(StatusNeedsUpdate);
				tally.remove(NetworkNeedsUpdate);
				// If WPA_EVENT_TERMINATING not arrive check networks anyway
			    QTimer::singleShot(BorderCollie, this, SLOT(updateNetworks()));
			}
			// Needed to get inactive status (if so) or if
			// WPA_EVENT_TERMINATING not arrive check anyway
			QTimer::singleShot(BorderCollie, this, SLOT(updateStatus()));
		} else if (strstr(pos, "reason=4")) {
			setState(WpaLostSignal);
			showTrayMessage(tr("Lost signal"), QSystemTrayIcon::Warning);
		} else {
			debug("WARNING disconnect reason not handled/ignored");
		}
	} else if (str_match(pos, WPA_EVENT_CONNECTED)) {
		setState(WpaCompleted);
		showTrayMessage(tr("Connection to network established"));
		// Needed to ensure IP is read
		QTimer::singleShot(BorderCollie, this, SLOT(updateStatus()));
	} else if (str_match(pos, WPA_EVENT_TERMINATING)) {
		setState(WpaNotRunning);
		showTrayMessage(tr("The wpa_supplicant is terminated")
		              , QSystemTrayIcon::Critical);
	} else if (str_match(pos, WPS_EVENT_AP_AVAILABLE_PBC)) {
		logHint(tr("WPS AP in active PBC mode found"));
		if (WpaInactive == wpaState || WpaDisconnected == wpaState) {
			wpaguiTab->setCurrentWidget(wpsTab);
			setState(WpaWait4Registrar);
		}
		wpsInstructions->setText(tr("Press the PBC button on the "
		                            "screen to start registration"));
	} else if (str_match(pos, WPS_EVENT_AP_AVAILABLE_PIN)) {
		logHint(tr("WPS AP with recently selected registrar"));
		if (WpaInactive == wpaState || WpaDisconnected == wpaState)
			wpaguiTab->setCurrentWidget(wpsTab);
	} else if (str_match(pos, WPS_EVENT_AP_AVAILABLE_AUTH)) {
		showTrayMessage("Wi-Fi Protected Setup (WPS) AP\n"
		                "indicating this client is authorized");
		logHint("WPS AP indicating this client is authorized");
		if (WpaInactive == wpaState || WpaDisconnected == wpaState)
			wpaguiTab->setCurrentWidget(wpsTab);
	} else if (str_match(pos, WPS_EVENT_AP_AVAILABLE)) {
		logHint(tr("WPS AP detected"));
	} else if (str_match(pos, WPS_EVENT_OVERLAP)) {
		logHint(tr("PBC mode overlap detected"));
		wpsInstructions->setText(tr("More than one AP is currently in "
		                            "active WPS PBC mode. Wait couple "
		                            "of minutes and try again"));
		wpaguiTab->setCurrentWidget(wpsTab);
	} else if (str_match(pos, WPS_EVENT_CRED_RECEIVED)) {
		logHint(tr("Network configuration received"));
		wpaguiTab->setCurrentWidget(wpsTab);
	} else if (str_match(pos, WPA_EVENT_EAP_METHOD)) {
		if (strstr(pos, "(WSC)"))
			logHint(tr("Registration started"));
	} else if (str_match(pos, WPS_EVENT_M2D)) {
		logHint(tr("Registrar does not yet know PIN"));
	} else if (str_match(pos, WPS_EVENT_FAIL)) {
		logHint(tr("Registration failed"));
	} else if (str_match(pos, WPS_EVENT_SUCCESS)) {
		logHint(tr("Registration succeeded"));
	} else if (str_match(pos, WPA_EVENT_BSS_REMOVED)) {
		// Needed to catch these or the next has not the desired effect to...
		debug("Message noticed but so far ignored");
	} else if (WpaUnknown == wpaState) {
		// ...catch the buggy wpa_supplicant behavior when shut down
		setState(WpaRunning);
	} else {
		debug("Message ignored");
	}
}


void WpaGui::processCtrlReq(const char *req)
{
	if (udr) {
		udr->close();
		delete udr;
	}
	udr = new UserDataRequest();
	if (udr == NULL)
		return;
	if (udr->setParams(this, req) < 0) {
		delete udr;
		udr = NULL;
		return;
	}
	udr->show();
	udr->exec();
}


void WpaGui::receiveMsgs()
{
	char buf[256];
	size_t len;

	debug("receiveMsgs() >>>");

	while (monitor_conn && wpa_ctrl_pending(monitor_conn) > 0) {
		len = sizeof(buf) - 1;
		if (wpa_ctrl_recv(monitor_conn, buf, &len) == 0) {
			buf[len] = '\0';
			processMsg(buf);
		}
	}
	debug("receiveMsgs() >>>>>>");

	updateStatus(tally.contains(StatusNeedsUpdate));
	updateNetworks(tally.contains(NetworkNeedsUpdate));

	debug("receiveMsgs() <<<<<<");
}


void WpaGui::networkSelectionChanged()
{
	QTreeWidgetItem *selectedNetwork = networkList->currentItem();
	if (!selectedNetwork) {
		debug("networkSelectionChanged - NULL");
		networkEditAction->setEnabled(false);
		networkRemoveAction->setEnabled(false);
		networkDisEnableAction->setEnabled(false);
		networkDisEnableAction->setText(tr("Dis-/Enable"));
		return;
	}
	networkEditAction->setEnabled(true);
	networkRemoveAction->setEnabled(true);
	networkDisEnableAction->setEnabled(true);

	switch (getNetworkDisabled(selectedNetwork->text(0))) {
		case 1:
			networkDisEnableAction->setText(tr("Enable"));
			break;
		case 0:
			networkDisEnableAction->setText(tr("Disable"));
			break;
		default:
			networkDisEnableAction->setEnabled(false);  // TODO Hint user
			break;
	}
}


void WpaGui::enableNetwork(const QString &sel)
{
	requestNetworkChange("ENABLE_NETWORK ", sel);
}


void WpaGui::disableNetwork(const QString &sel)
{
	requestNetworkChange("DISABLE_NETWORK ", sel);
}


void WpaGui::requestNetworkChange(const QString &req, const QString &sel)
{
	QString cmd(sel);
	char reply[10];
	size_t reply_len = sizeof(reply);

	if (cmd.compare("all") != 0) {
		if (!QRegExp("^\\d+").exactMatch(cmd)) {
			debug("Invalid request target: %s '%s'",
			      req.toLocal8Bit().constData(),
			      cmd.toLocal8Bit().constData());
			return;
		}
	}
	cmd.prepend(req);
	ctrlRequest(cmd.toLocal8Bit().constData(), reply, &reply_len);

	updateNetworks();
}


void WpaGui::editNetwork(const QString &sel)
{
	QString cmd(sel);
	int id = -1;

	id = cmd.toInt();

	NetworkConfig *nc = new NetworkConfig();
	if (nc == NULL)
		return;
	nc->setWpaGui(this);

	if (id >= 0)
		nc->paramsFromConfig(id);
	else
		nc->newNetwork();

	nc->show();
	nc->exec();
}


void WpaGui::editListedNetwork()
{
	if (!networkList->currentItem()) {
		QMessageBox::information(this, tr("Select A Network"),
					 tr("Select a network from the list to"
					    " edit it.\n"));
		return;
	}
	QString sel(networkList->currentItem()->text(0));
	editNetwork(sel);
}


void WpaGui::addNetwork()
{
	NetworkConfig *nc = new NetworkConfig();
	if (nc == NULL)
		return;
	nc->setWpaGui(this);
	nc->newNetwork();
	nc->show();
	nc->exec();
}


void WpaGui::removeNetwork(const QString &sel)
{
	requestNetworkChange("REMOVE_NETWORK ", sel);
}


void WpaGui::removeListedNetwork()
{
	if (!networkList->currentItem()) {
		QMessageBox::information(this, tr("Select A Network"),
					 tr("Select a network from the list "
					    "to remove it.\n"));
		return;
	}

	QString sel(networkList->currentItem()->text(0));
	removeNetwork(sel);
}


void WpaGui::enableAllNetworks()
{
	QString sel("all");
	enableNetwork(sel);
}


void WpaGui::disableAllNetworks()
{
	QString sel("all");
	disableNetwork(sel);
}


void WpaGui::removeAllNetworks()
{
	QString sel("all");
	removeNetwork(sel);
}


int WpaGui::getNetworkDisabled(const QString &sel)
{
	QString cmd(sel);
	char reply[10];
	size_t reply_len = sizeof(reply) - 1;

	if (cmd.compare("all") != 0) {
		if (!QRegExp("^\\d+").exactMatch(cmd)) {
			debug("Invalid getNetworkDisabled '%s'",
				cmd.toLocal8Bit().constData());
			return -1;
		}
	}
	cmd.prepend("GET_NETWORK ");
	cmd.append(" disabled");

	if (ctrlRequest(cmd.toLocal8Bit().constData(), reply, &reply_len) >= 0
	    && reply_len >= 1) {
		reply[reply_len] = '\0';
		if (!str_match(reply, "FAIL"))
			return atoi(reply);
	}

	return -1;
}



void WpaGui::disEnableNetwork()
{
	QTreeWidgetItem *selectedNetwork = networkList->currentItem();
	switch (getNetworkDisabled(selectedNetwork->text(0))) {
	case 1:
		enableNetwork(selectedNetwork->text(0));
		break;
	case 0:
		disableNetwork(selectedNetwork->text(0));
		break;
	default:
		// We should never read this
		logHint("Oops?! Error after getNetworkDisabled() call");
		break;
	}

	updateStatus();
}


void WpaGui::saveConfig()
{
	char buf[10];
	size_t len;

	len = sizeof(buf) - 1;
	ctrlRequest("SAVE_CONFIG", buf, &len);

	buf[len] = '\0';

	if (str_match(buf, "FAIL"))
		QMessageBox::warning(
			this, tr("Failed to save configuration"),
			tr("The configuration could not be saved.\n"
			   "\n"
			   "The update_config=1 configuration option\n"
			   "must be used for configuration saving to\n"
			   "be permitted.\n"));
	else
		QMessageBox::information(
			this, tr("Saved configuration"),
			tr("The current configuration was saved."
			   "\n"));
}


void WpaGui::selectAdapter( const QString & sel )
{
	if (sel.compare(ctrl_iface) == 0)
		return;

	logHint(tr("User requests adapter change to %1").arg(sel));
	openCtrlConnection(sel.toLocal8Bit().constData());
	updateNetworks();
	updateStatus();
}


void WpaGui::createTrayIcon(bool trayOnly)
{
	QApplication::setQuitOnLastWindowClosed(false);

	tray_icon = new QSystemTrayIcon(this);
	updateTrayIcon(TrayIconOffline);

	connect(tray_icon, SIGNAL(activated(QSystemTrayIcon::ActivationReason))
	      , this, SLOT(trayActivated(QSystemTrayIcon::ActivationReason)));

	tally.remove(AckTrayIcon);

	tray_menu = new QMenu(this);

	QAction *statAction;
	statAction = new QAction(tr("S&tatus"), this);
	connect(statAction, SIGNAL(triggered()), this, SLOT(showTrayStatus()));
	tray_menu->addAction(statAction);
	tray_menu->addAction(disconReconAction);
	tray_menu->addSeparator();
	tray_menu->addAction(eventHistoryAction);
	tray_menu->addAction(scanAction);
	tray_menu->addSeparator();
	tray_menu->addAction(quitAction);

	tray_icon->setContextMenu(tray_menu);
	tray_icon->show();

	if (trayOnly)
		tally.insert(InTray);
	else
		show();
}


void WpaGui::showTrayMessage(const QString &msg
	       , QSystemTrayIcon::MessageIcon type/* = QSystemTrayIcon::Information*/
	       , int sec/* = 5*/)
{
	logHint(msg);

	if (!QSystemTrayIcon::supportsMessages())
		return;

	if (isVisible() || !tray_icon || !tray_icon->isVisible() || tally.contains(QuietMode))
		return;

	tray_icon->showMessage(qAppName(), msg, type, sec * 1000);
}


void WpaGui::trayActivated(QSystemTrayIcon::ActivationReason how)
 {
	switch (how) {
	/* use close() here instead of hide() and allow the
	 * custom closeEvent handler take care of children */
	case QSystemTrayIcon::Trigger:
		tally.insert(AckTrayIcon);
		if (isVisible()) {
			close();
			tally.insert(InTray);
		} else {
			show();
			activateWindow();
			tally.remove(InTray);
		}
		break;
	case QSystemTrayIcon::MiddleClick:
		showTrayStatus();
		break;
	default:
		break;
	}
}


void WpaGui::showTrayStatus()
{
	char buf[2048];
	size_t len;

	len = sizeof(buf) - 1;
	if (ctrlRequest("STATUS", buf, &len) < 0)
		return;
	buf[len] = '\0';

	QString msg, status(buf);

	QStringList lines = status.split(QRegExp("\\n"));
	for (QStringList::Iterator it = lines.begin();
	     it != lines.end(); it++) {
		int pos = (*it).indexOf('=') + 1;
		if (pos < 1)
			continue;

		if ((*it).startsWith("bssid="))
			msg.append("BSSID:\t" + (*it).mid(pos) + "\n");
		else if ((*it).startsWith("ssid="))
			msg.append("SSID: \t" + (*it).mid(pos) + "\n");
		else if ((*it).startsWith("pairwise_cipher="))
			msg.append("PAIR: \t" + (*it).mid(pos) + "\n");
		else if ((*it).startsWith("group_cipher="))
			msg.append("GROUP:\t" + (*it).mid(pos) + "\n");
		else if ((*it).startsWith("key_mgmt="))
			msg.append("AUTH: \t" + (*it).mid(pos) + "\n");
		else if ((*it).startsWith("wpa_state="))
			msg.append("STATE:\t" + (*it).mid(pos) + "\n");
		else if ((*it).startsWith("ip_address="))
			msg.append("IP:   \t" + (*it).mid(pos) + "\n");
		else if ((*it).startsWith("Supplicant PAE state="))
			msg.append("PAE:  \t" + (*it).mid(pos) + "\n");
		else if ((*it).startsWith("EAP state="))
			msg.append("EAP:  \t" + (*it).mid(pos) + "\n");
	}

	if (!msg.isEmpty())
		showTrayMessage(msg);
}


void WpaGui::updateTrayToolTip(const QString &msg)
{
	if (!tray_icon)
		return;

	if (WpaCompleted == wpaState)
		tray_icon->setToolTip(QString("%1 - %2")
		                     .arg(ctrl_iface)
		                     .arg(textSsid->text()));
	else if (ctrl_iface)
		tray_icon->setToolTip(QString("%1 - %2")
		                     .arg(ctrl_iface).arg(msg));
	else
		tray_icon->setToolTip(QString("%1 - %2")
		                     .arg(qAppName()).arg(msg));
}


void WpaGui::updateTrayIcon(const TrayIconType type)
{
	static TrayIconType oldIconType(TrayIconNone);
	QStringList names;
	QIcon fallback_icon;


	if (!tray_icon || type == oldIconType)
		return;

	oldIconType = type;

	if (QImageReader::supportedImageFormats().contains(QByteArray("svg")))
		fallback_icon = QIcon(":/icons/wpa_gui.svg");
	else
		fallback_icon = QIcon(":/icons/wpa_gui.png");

	switch (type) {
	case TrayIconNone:
		return;
		break;
	case TrayIconError:
		names << "error"
		      << "network-wireless-offline-symbolic";
		break;
	case TrayIconOffline:
		names << "network-wireless-disconnected"
		      << "network-wireless-offline-symbolic";
		break;
	case TrayIconInactive:
		names << "network-wireless-disconnected"
		      << "network-wireless-offline-symbolic";
		break;
	case TrayIconScanning:
		names << "network-wireless-acquiring"
		      << "network-wireless-acquiring-symbolic";
		break;
	case TrayIconAcquiring:
		names << "network-wireless-acquiring"
		      << "network-wireless-acquiring-symbolic";
		break;
	case TrayIconConnected:
		names << "network-wireless-connected-00"
		      << "network-wireless-connected-symbolic";
		break;
	case TrayIconSignalNone:
		names << "network-wireless-signal-none"
		      << "network-wireless-signal-none-symbolic";
		break;
	case TrayIconSignalWeak:
		names << "network-wireless-signal-weak"
		      << "network-wireless-signal-weak-symbolic";
		break;
	case TrayIconSignalOk:
		names << "network-wireless-signal-ok"
		      << "network-wireless-signal-ok-symbolic";
		break;
	case TrayIconSignalGood:
		names << "network-wireless-signal-good"
		      << "network-wireless-signal-good-symbolic";
		break;
	case TrayIconSignalExcellent:
		names << "network-wireless-connected-100"
		      << "network-wireless-signal-excellent-symbolic";
		break;
	}

	tray_icon->setIcon(loadThemedIcon(names, fallback_icon));
}


QIcon WpaGui::loadThemedIcon(const QStringList &names,
			     const QIcon &fallback)
{
	QIcon icon;

	for (QStringList::ConstIterator it = names.begin();
	     it != names.end(); it++) {
		icon = QIcon::fromTheme(*it);
		if (!icon.isNull())
			return icon;
	}

	return fallback;
}


void WpaGui::closeEvent(QCloseEvent *event)
{
	if (eh) {
		eh->close();
		delete eh;
		eh = NULL;
	}

	if (scanres) {
		scanres->close();
		delete scanres;
		scanres = NULL;
	}

	if (peers) {
		peers->close();
		delete peers;
		peers = NULL;
	}

	if (udr) {
		udr->close();
		delete udr;
		udr = NULL;
	}

	if (tray_icon && !tally.contains(AckTrayIcon)) {
		/* give user a visual hint that the tray icon exists */
		if (QSystemTrayIcon::supportsMessages()) {
			hide();
			showTrayMessage(tr("I will keep running in the system tray"));
		} else {
			QMessageBox::information(this, qAppName() +
						 tr(" systray"),
						 tr("The program will keep "
						    "running in the system "
						    "tray"));
		}
		tally.insert(AckTrayIcon);
	}

	event->accept();
}


void WpaGui::showEvent(QShowEvent *event)
{
    letTheDogOut(BorderCollie, enablePollingAction->isChecked());
	event->ignore();
}


void WpaGui::wpsDialog()
{
	wpaguiTab->setCurrentWidget(wpsTab);
}


void WpaGui::peersDialog()
{
	if (peers) {
		peers->close();
		delete peers;
	}

	peers = new Peers();
	if (peers == NULL)
		return;
	peers->setWpaGui(this);
	peers->show();
	peers->exec();
}


void WpaGui::tabChanged(int index)
{
	if (index != 2)
		return;

	if (tally.contains(WpsRunning))
		return;

	wpsApPinEdit->setEnabled(!bssFromScan.isEmpty());
	if (bssFromScan.isEmpty())
		wpsApPinButton->setEnabled(false);
}


void WpaGui::wpsPbc()
{
	char reply[20];
	size_t reply_len = sizeof(reply);

	if (ctrlRequest("WPS_PBC", reply, &reply_len) < 0)
		return;

	wpsPinEdit->setEnabled(false);
	if (WpaWait4Registrar != wpaState) {
		wpsInstructions->setText(tr("Press the push button on the AP to "
					 "start the PBC mode."));
	} else {
		wpsInstructions->setText(tr("If you have not yet done so, press "
					 "the push button on the AP to start "
					 "the PBC mode."));
	}
	logHint(tr("Waiting for Registrar"));
	tally.insert(WpsRunning);
}


void WpaGui::wpsGeneratePin()
{
	char reply[20];
	size_t reply_len = sizeof(reply) - 1;

	if (ctrlRequest("WPS_PIN any", reply, &reply_len) < 0)
		return;

	reply[reply_len] = '\0';

	wpsPinEdit->setText(reply);
	wpsPinEdit->setEnabled(true);
	wpsInstructions->setText(tr("Enter the generated PIN into the Registrar "
				 "(either the internal one in the AP or an "
				 "external one)."));
	logHint(tr("Waiting for Registrar"));
	tally.insert(WpsRunning);
}


void WpaGui::setBssFromScan(const QString &bssid)
{
	bssFromScan = bssid;
	wpsApPinEdit->setEnabled(!bssFromScan.isEmpty());
	wpsApPinButton->setEnabled(wpsApPinEdit->text().length() == 8);
	logHint(tr("WPS AP selected from scan results"));
	wpsInstructions->setText(tr("If you want to use an AP device PIN, e.g., "
				 "from a label in the device, enter the eight "
				 "digit AP PIN and click Use AP PIN button."));
}


void WpaGui::wpsApPinChanged(const QString &text)
{
	wpsApPinButton->setEnabled(text.length() == 8);
}


void WpaGui::wpsApPin()
{
	char reply[20];
	size_t reply_len = sizeof(reply);

	QString cmd("WPS_REG " + bssFromScan + " " + wpsApPinEdit->text());
	if (ctrlRequest(cmd.toLocal8Bit().constData(), reply, &reply_len) < 0)
		return;

	logHint(tr("Waiting for AP/Enrollee"));
	tally.insert(WpsRunning);
}


void WpaGui::stopWpsRun(bool success)
{
	if (tally.contains(WpsRunning))
		logHint(success ? tr("Connected to the network") :
		                  tr("Stopped"));

	wpsPinEdit->setEnabled(false);
	wpsInstructions->setText("");
	tally.remove(WpsRunning);
	bssFromScan = "";
	wpsApPinEdit->setEnabled(false);
	wpsApPinButton->setEnabled(false);
}


#ifdef CONFIG_NATIVE_WINDOWS

#ifndef WPASVC_NAME
#define WPASVC_NAME TEXT("wpasvc")
#endif

class ErrorMsg : public QMessageBox {
public:
	ErrorMsg(QWidget *parent, DWORD last_err = GetLastError());
	void showMsg(QString msg);
private:
	DWORD err;
};

ErrorMsg::ErrorMsg(QWidget *parent, DWORD last_err) :
	QMessageBox(parent), err(last_err)
{
	setWindowTitle(tr("wpa_gui error"));
	setIcon(QMessageBox::Warning);
}

void ErrorMsg::showMsg(QString msg)
{
	LPTSTR buf;

	setText(msg);
	if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
			  FORMAT_MESSAGE_FROM_SYSTEM,
			  NULL, err, 0, (LPTSTR) (void *) &buf,
			  0, NULL) > 0) {
		QString msg = QString::fromWCharArray(buf);
		setInformativeText(QString("[%1] %2").arg(err).arg(msg));
		LocalFree(buf);
	} else {
		setInformativeText(QString("[%1]").arg(err));
	}

	exec();
}


void WpaGui::startService()
{
	SC_HANDLE svc, scm;

	scm = OpenSCManager(0, 0, SC_MANAGER_CONNECT);
	if (!scm) {
		ErrorMsg(this).showMsg(tr("OpenSCManager failed"));
		return;
	}

	svc = OpenService(scm, WPASVC_NAME, SERVICE_START);
	if (!svc) {
		ErrorMsg(this).showMsg(tr("OpenService failed"));
		CloseServiceHandle(scm);
		return;
	}

	if (!StartService(svc, 0, NULL)) {
		ErrorMsg(this).showMsg(tr("Failed to start wpa_supplicant "
				       "service"));
	}

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
}


void WpaGui::stopService()
{
	SC_HANDLE svc, scm;
	SERVICE_STATUS status;

	scm = OpenSCManager(0, 0, SC_MANAGER_CONNECT);
	if (!scm) {
		ErrorMsg(this).showMsg(tr("OpenSCManager failed"));
		return;
	}

	svc = OpenService(scm, WPASVC_NAME, SERVICE_STOP);
	if (!svc) {
		ErrorMsg(this).showMsg(tr("OpenService failed"));
		CloseServiceHandle(scm);
		return;
	}

	if (!ControlService(svc, SERVICE_CONTROL_STOP, &status)) {
		ErrorMsg(this).showMsg(tr("Failed to stop wpa_supplicant "
				       "service"));
	}

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);
}


bool WpaGui::serviceRunning()
{
	SC_HANDLE svc, scm;
	SERVICE_STATUS status;
	bool running = false;

	scm = OpenSCManager(0, 0, SC_MANAGER_CONNECT);
	if (!scm) {
		debug("OpenSCManager failed: %d", (int) GetLastError());
		return false;
	}

	svc = OpenService(scm, WPASVC_NAME, SERVICE_QUERY_STATUS);
	if (!svc) {
		debug("OpenService failed: %d", (int) GetLastError());
		CloseServiceHandle(scm);
		return false;
	}

	if (QueryServiceStatus(svc, &status)) {
		if (status.dwCurrentState != SERVICE_STOPPED)
			running = true;
	}

	CloseServiceHandle(svc);
	CloseServiceHandle(scm);

	return running;
}

void WpaGui::addInterface()
{
	if (add_iface) {
		add_iface->close();
		delete add_iface;
	}
	add_iface = new AddInterface(this, this);
	add_iface->show();
	add_iface->exec();
}

#endif /* CONFIG_NATIVE_WINDOWS */

#ifndef QT_NO_SESSIONMANAGER
void WpaGui::saveState()
{
	QSettings settings("wpa_supplicant", "wpa_gui");
	settings.beginGroup("state");
	settings.setValue("session_id", app->sessionId());
	settings.setValue("in_tray", tally.contains(InTray));
	settings.endGroup();
}
#endif

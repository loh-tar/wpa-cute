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

#include <cstdio>
#include <QMessageBox>

#include "networkconfig.h"
#include "wpagui.h"

enum {
	AUTH_NONE_OPEN,
	AUTH_NONE_WEP,
	AUTH_NONE_WEP_SHARED,
	AUTH_IEEE8021X,
	AUTH_WPA_PSK,
	AUTH_WPA_EAP,
	AUTH_WPA2_PSK,
	AUTH_WPA2_EAP,
	AUTH_DEFAULTS
};

#define WPA_GUI_KEY_DATA "[key is configured]"


NetworkConfig::NetworkConfig(QWidget *parent, const char *, bool,
			     Qt::WindowFlags)
	: QDialog(parent)
{
	setupUi(this);

	encrBox->setVisible(false);
	connect(authSelect, SIGNAL(activated(int)), this,
		SLOT(authChanged(int)));
	connect(cancelButton, SIGNAL(clicked()), this, SLOT(close()));
	connect(addButton, SIGNAL(clicked()), this, SLOT(addNetwork()));
	connect(encrSelect, SIGNAL(activated(const QString &)), this,
		SLOT(encrChanged(const QString &)));
	connect(removeButton, SIGNAL(clicked()), this, SLOT(removeNetwork()));
	connect(eapSelect, SIGNAL(activated(int)), this,
		SLOT(eapChanged(int)));
	connect(useWpsButton, SIGNAL(clicked()), this, SLOT(useWps()));

	wpagui = NULL;
	new_network = false;
}


NetworkConfig::~NetworkConfig()
{
}


void NetworkConfig::languageChange()
{
	retranslateUi(this);
}


void NetworkConfig::paramsFromScanResults(QTreeWidgetItem *sel)
{
	new_network = true;

	/* SSID BSSID frequency signal flags */
	setWindowTitle(sel->text(0));
	ssidEdit->setText(sel->text(0));

	QString flags = sel->text(4);
	int auth, encr = 0;
	if (flags.indexOf("[WPA2-EAP") >= 0)
		auth = AUTH_WPA2_EAP;
	else if (flags.indexOf("[WPA-EAP") >= 0)
		auth = AUTH_WPA_EAP;
	else if (flags.indexOf("[WPA2-PSK") >= 0)
		auth = AUTH_WPA2_PSK;
	else if (flags.indexOf("[WPA-PSK") >= 0)
		auth = AUTH_WPA_PSK;
	else
		auth = AUTH_NONE_OPEN;

	if (flags.indexOf("-CCMP") >= 0)
		encr = 1;
	else if (flags.indexOf("-TKIP") >= 0)
		encr = 0;
	else if (flags.indexOf("WEP") >= 0) {
		encr = 1;
		if (auth == AUTH_NONE_OPEN)
			auth = AUTH_NONE_WEP;
	} else
		encr = 0;

	authSelect->setCurrentIndex(auth);
	authChanged(auth);
	encrSelect->setCurrentIndex(encr);

	wepEnabled(auth == AUTH_NONE_WEP);

	getEapCapa();

	if (flags.indexOf("[WPS") >= 0)
		useWpsButton->setEnabled(true);
	bssid = sel->text(1);
}


void NetworkConfig::authChanged(int sel)
{
	encrBox->setVisible(sel != AUTH_NONE_OPEN && sel != AUTH_NONE_WEP &&
			       sel != AUTH_NONE_WEP_SHARED && sel != AUTH_IEEE8021X);
	pskBox->setVisible(sel == AUTH_WPA_PSK || sel == AUTH_WPA2_PSK ||
		sel == AUTH_DEFAULTS);
	bool eap = sel == AUTH_IEEE8021X || sel == AUTH_WPA_EAP ||
		sel == AUTH_WPA2_EAP;
	eapBox->setVisible(eap);
	resize(sizeHint());
	adjustSize();
	eapSelect->setEnabled(eap);
	identityEdit->setEnabled(eap);
	passwordEdit->setEnabled(eap);
	cacertEdit->setEnabled(eap);
	phase2Select->setEnabled(eap);
	if (eap)
		eapChanged(eapSelect->currentIndex());

	encrSelect->clear();

	if (sel == AUTH_NONE_OPEN || sel == AUTH_NONE_WEP ||
	    sel == AUTH_NONE_WEP_SHARED || sel == AUTH_IEEE8021X) {
		encrSelect->addItem("None");
		encrSelect->addItem("WEP");
		encrSelect->setCurrentIndex(sel == AUTH_NONE_OPEN ? 0 : 1);
	} else {
		encrSelect->addItem("TKIP");
		encrSelect->addItem("CCMP");
		if (sel == AUTH_DEFAULTS) {
			encrSelect->addItem("CCMP TKIP");
			encrSelect->setCurrentIndex(2);
		}
		else {
		encrSelect->setCurrentIndex((sel == AUTH_WPA2_PSK ||
		                             sel == AUTH_WPA2_EAP ) ? 1 : 0);
		}
	}

	wepEnabled(sel == AUTH_NONE_WEP || sel == AUTH_NONE_WEP_SHARED);
}


void NetworkConfig::eapChanged(int sel)
{
	QString prev_val = phase2Select->currentText();
	while (phase2Select->count())
		phase2Select->removeItem(0);

	QStringList inner;
	inner << "PEAP" << "TTLS" << "FAST";
	if (!inner.contains(eapSelect->itemText(sel)))
		return;

	phase2Select->addItem("[ any ]");

	/* Add special cases based on outer method */
	if (eapSelect->currentText().compare("TTLS") == 0) {
		phase2Select->addItem("PAP");
		phase2Select->addItem("CHAP");
		phase2Select->addItem("MSCHAP");
		phase2Select->addItem("MSCHAPv2");
	} else if (eapSelect->currentText().compare("FAST") == 0)
		phase2Select->addItem("GTC(auth) + MSCHAPv2(prov)");

	/* Add all enabled EAP methods that can be used in the tunnel */
	int i;
	QStringList allowed;
	allowed << "MSCHAPV2" << "MD5" << "GTC" << "TLS" << "OTP" << "SIM"
		<< "AKA";
	for (i = 0; i < eapSelect->count(); i++) {
		if (allowed.contains(eapSelect->itemText(i))) {
			phase2Select->addItem("EAP-" + eapSelect->itemText(i));
		}
	}

	for (i = 0; i < phase2Select->count(); i++) {
		if (phase2Select->itemText(i).compare(prev_val) == 0) {
			phase2Select->setCurrentIndex(i);
			break;
		}
	}
}


void NetworkConfig::addNetwork()
{
	size_t len(10); char buf[len];
	int id;
	int psklen = pskEdit->text().length();
	int auth = authSelect->currentIndex();

	if (auth == AUTH_WPA_PSK || auth == AUTH_WPA2_PSK) {
		if (psklen < 8 || psklen > 64) {
			QMessageBox::warning(
				this,
				tr("WPA Pre-Shared Key Error"),
				tr("WPA-PSK requires a passphrase of 8 to 63 "
				   "characters\n"
				   "or 64 hex digit PSK"));
			pskEdit->setFocus();
			return;
		}
	}

	if (idstrEdit->isEnabled() && !idstrEdit->text().isEmpty()) {
		QRegExp rx("^(\\w|-)+$");
		if (rx.indexIn(idstrEdit->text()) < 0) {
			QMessageBox::warning(
				this, tr("Network ID Error"),
				tr("Network ID String contains non-word "
				   "characters.\n"
				   "It must be a simple string, "
				   "without spaces, containing\n"
				   "only characters in this range: "
				   "[A-Za-z0-9_-]\n"));
			idstrEdit->setFocus();
			return;
		}
	}

	if (wpagui == NULL)
		return;

	memset(buf, 0, sizeof(buf));

	if (new_network) {
		if (wpagui->ctrlRequest("ADD_NETWORK", buf, len) < 0) {
			QMessageBox::warning(this, ProjAppName,
			                     tr("Failed to add network to \n"
			                        "wpa_supplicant configuration."));
			return;
		}
		id = atoi(buf);
	} else
		id = edit_network_id;

	setNetworkParam(id, "ssid", ssidEdit->text().toLocal8Bit().constData()
	              , true);

	const char *key_mgmt = NULL, *proto = NULL, *pairwise = NULL;
	switch (auth) {
	case AUTH_NONE_OPEN:
	case AUTH_NONE_WEP:
	case AUTH_NONE_WEP_SHARED:
		key_mgmt = "NONE";
		break;
	case AUTH_IEEE8021X:
		key_mgmt = "IEEE8021X";
		break;
	case AUTH_WPA_PSK:
		key_mgmt = "WPA-PSK";
		proto = "WPA";
		break;
	case AUTH_WPA_EAP:
		key_mgmt = "WPA-EAP";
		proto = "WPA";
		break;
	case AUTH_WPA2_PSK:
		key_mgmt = "WPA-PSK";
		proto = "WPA2";
		break;
	case AUTH_WPA2_EAP:
		key_mgmt = "WPA-EAP";
		proto = "WPA2";
		break;
	}

	if (auth == AUTH_NONE_WEP_SHARED)
		setNetworkParam(id, "auth_alg", "SHARED", false);
	else
		setNetworkParam(id, "auth_alg", "OPEN", false);

	if (auth == AUTH_WPA_PSK || auth == AUTH_WPA_EAP ||
	    auth == AUTH_WPA2_PSK || auth == AUTH_WPA2_EAP) {
		int encr = encrSelect->currentIndex();
		if (encr == 0)
			pairwise = "TKIP";
		else
			pairwise = "CCMP";
	}

	if (proto)
		setNetworkParam(id, "proto", proto, false);
	if (key_mgmt)
		setNetworkParam(id, "key_mgmt", key_mgmt, false);
	if (pairwise) {
		setNetworkParam(id, "pairwise", pairwise, false);
		setNetworkParam(id, "group", "TKIP CCMP WEP104 WEP40", false);
	}
	if (pskBox->isVisible() &&
	    strcmp(pskEdit->text().toLocal8Bit().constData(),
		   WPA_GUI_KEY_DATA) != 0)
		setNetworkParam(id, "psk",
				pskEdit->text().toLocal8Bit().constData(),
				psklen != 64);
	if (eapSelect->isEnabled()) {
		const char *eap =
			eapSelect->currentText().toLocal8Bit().constData();
		setNetworkParam(id, "eap", eap, false);
		if (strcmp(eap, "SIM") == 0 || strcmp(eap, "AKA") == 0)
			setNetworkParam(id, "pcsc", "", true);
		else
			setNetworkParam(id, "pcsc", "NULL", false);
	}
		else
			setNetworkParam(id, "eap", "NULL", false);
	if (phase2Select->isEnabled()) {
		QString eap = eapSelect->currentText();
		QString inner = phase2Select->currentText();
		char phase2[32];
		phase2[0] = '\0';
		if (eap.compare("PEAP") == 0) {
			if (inner.startsWith("EAP-"))
				snprintf(phase2, sizeof(phase2), "auth=%s",
					 inner.right(inner.size() - 4).
					 toLocal8Bit().constData());
		} else if (eap.compare("TTLS") == 0) {
			if (inner.startsWith("EAP-"))
				snprintf(phase2, sizeof(phase2), "autheap=%s",
					 inner.right(inner.size() - 4).
					 toLocal8Bit().constData());
			else
				snprintf(phase2, sizeof(phase2), "auth=%s",
					 inner.toLocal8Bit().constData());
		} else if (eap.compare("FAST") == 0) {
			const char *provisioning = NULL;
			if (inner.startsWith("EAP-")) {
				snprintf(phase2, sizeof(phase2), "auth=%s",
					 inner.right(inner.size() - 4).
					 toLocal8Bit().constData());
				provisioning = "fast_provisioning=2";
			} else if (inner.compare("GTC(auth) + MSCHAPv2(prov)")
				   == 0) {
				snprintf(phase2, sizeof(phase2),
					 "auth=GTC auth=MSCHAPV2");
				provisioning = "fast_provisioning=1";
			} else
				provisioning = "fast_provisioning=3";
			if (provisioning) {
				char blob[32];
				setNetworkParam(id, "phase1", provisioning,
						true);
				snprintf(blob, sizeof(blob),
					 "blob://fast-pac-%d", id);
				setNetworkParam(id, "pac_file", blob, true);
			}
		}
		if (phase2[0])
			setNetworkParam(id, "phase2", phase2, true);
		else
			setNetworkParam(id, "phase2", "NULL", false);
	} else
		setNetworkParam(id, "phase2", "NULL", false);
	if (identityEdit->isEnabled() && identityEdit->text().length() > 0)
		setNetworkParam(id, "identity",
				identityEdit->text().toLocal8Bit().constData(),
				true);
	else
		setNetworkParam(id, "identity", "NULL", false);
	if (passwordEdit->isEnabled() && passwordEdit->text().length() > 0 &&
	    strcmp(passwordEdit->text().toLocal8Bit().constData(),
		   WPA_GUI_KEY_DATA) != 0)
		setNetworkParam(id, "password",
				passwordEdit->text().toLocal8Bit().constData(),
				true);
	else if (passwordEdit->text().length() == 0)
		setNetworkParam(id, "password", "NULL", false);
	if (cacertEdit->isEnabled() && cacertEdit->text().length() > 0)
		setNetworkParam(id, "ca_cert",
				cacertEdit->text().toLocal8Bit().constData(),
				true);
	else
		setNetworkParam(id, "ca_cert", "NULL", false);
	writeWepKey(id, wep0Edit, 0);
	writeWepKey(id, wep1Edit, 1);
	writeWepKey(id, wep2Edit, 2);
	writeWepKey(id, wep3Edit, 3);

	if (wep0Radio->isEnabled() && wep0Radio->isChecked())
		setNetworkParam(id, "wep_tx_keyidx", "0", false);
	else if (wep1Radio->isEnabled() && wep1Radio->isChecked())
		setNetworkParam(id, "wep_tx_keyidx", "1", false);
	else if (wep2Radio->isEnabled() && wep2Radio->isChecked())
		setNetworkParam(id, "wep_tx_keyidx", "2", false);
	else if (wep3Radio->isEnabled() && wep3Radio->isChecked())
		setNetworkParam(id, "wep_tx_keyidx", "3", false);

	if (idstrEdit->isEnabled() && idstrEdit->text().length() > 0)
		setNetworkParam(id, "id_str",
				idstrEdit->text().toLocal8Bit().constData(),
				true);
	else
		setNetworkParam(id, "id_str", "NULL", false);

	if (prioritySpinBox->isEnabled()) {
		QString prio;
		prio = prio.setNum(prioritySpinBox->value());
		setNetworkParam(id, "priority", prio.toLocal8Bit().constData(),
				false);
	}

	wpagui->enableNetwork(QString::number(id));

	close();
}


void NetworkConfig::setWpaGui(WpaGui *_wpagui)
{
	wpagui = _wpagui;
}


int NetworkConfig::setNetworkParam(int id, const char *field,
                                   const char *value, bool quote)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "SET_NETWORK %d %s %s%s%s",
		 id, field, quote ? "\"" : "", value, quote ? "\"" : "");
	return wpagui->ctrlRequest(cmd);
}


void NetworkConfig::encrChanged(const QString &)
{
}


void NetworkConfig::wepEnabled(bool enabled)
{
	wepBox->setVisible(enabled);
	resize(sizeHint());
	adjustSize();
	wep0Edit->setEnabled(enabled);
	wep1Edit->setEnabled(enabled);
	wep2Edit->setEnabled(enabled);
	wep3Edit->setEnabled(enabled);
	wep0Radio->setEnabled(enabled);
	wep1Radio->setEnabled(enabled);
	wep2Radio->setEnabled(enabled);
	wep3Radio->setEnabled(enabled);
}


void NetworkConfig::writeWepKey(int network_id, QLineEdit *edit, int id)
{
	bool hex;
	size_t len;

	if (!edit->isEnabled())
		return;

	/*
	 * Assume hex key if only hex characters are present and length matches
	 * with 40, 104, or 128-bit key
	 */
	QString val = edit->text();
	if (val.compare(WPA_GUI_KEY_DATA) == 0)
		return;
	len = val.size();
	hex = val.contains(QRegExp("^[0-9A-F]+$"));

	if (hex && len != 10 && len != 26 && len != 32)
		hex = false;
	QString var("wep_key%1");
	setNetworkParam(network_id, var.arg(id), val, !hex);
}


void NetworkConfig::paramsFromConfig(int network_id)
{
	int i, res;

	edit_network_id = network_id;
	getEapCapa();

	QString curSetting(tr("Currently Used") + ": ");

	size_t len(1024); char buf[len];
	char *pos;
	QString cmd("GET_NETWORK %1 %2");
	cmd = cmd.arg(network_id);

	if (wpagui->ctrlRequest(cmd.arg("ssid"), buf, len) >= 0) {
		pos = strchr(buf + 1, '"');
		if (pos)
			*pos = '\0';
		ssidEdit->setText(buf + 1);
	}

	int wpa = 0;
	if (wpagui->ctrlRequest(cmd.arg("proto"), buf, len) >= 0) {
		if (strstr(buf, "RSN") || strstr(buf, "WPA2"))
			wpa = 2;
		else if (strstr(buf, "WPA"))
			wpa = 1;
	}

	int auth = AUTH_NONE_OPEN, encr = 0;
	if (wpagui->ctrlRequest(cmd.arg("key_mgmt"), buf, len) >= 0) {
		authSelect->setToolTip(curSetting + buf);
		if (strstr(buf, "WPA-PSK WPA-EAP")) {
			auth = AUTH_DEFAULTS;
			encr = 1;
		}
		else if (strstr(buf, "WPA-EAP"))
			auth = wpa & 2 ? AUTH_WPA2_EAP : AUTH_WPA_EAP;
		else if (strstr(buf, "WPA-PSK"))
			auth = wpa & 2 ? AUTH_WPA2_PSK : AUTH_WPA_PSK;
		else if (strstr(buf, "IEEE8021X")) {
			auth = AUTH_IEEE8021X;
			encr = 1;
		}
	}

	if (wpagui->ctrlRequest(cmd.arg("pairwise"), buf, len) >= 0) {
		encrSelect->setToolTip(curSetting + buf);
		if (strstr(buf, "CCMP TKIP"))
			encr = 2;
		else if (strstr(buf, "CCMP") && auth != AUTH_NONE_OPEN &&
		    auth != AUTH_NONE_WEP && auth != AUTH_NONE_WEP_SHARED)
			encr = 1;
		else if (strstr(buf, "TKIP"))
			encr = 0;
		else if (strstr(buf, "WEP"))
			encr = 1;
		else
			encr = 0;
	}

	res = wpagui->ctrlRequest(cmd.arg("psk"), buf, len);
	if (res >= 0 && buf[0] == '"') {
		pos = strchr(buf + 1, '"');
		if (pos)
			*pos = '\0';
		pskEdit->setText(buf + 1);
	} else if (res >= 0) {
		pskEdit->setText(WPA_GUI_KEY_DATA);
	}

	if (wpagui->ctrlRequest(cmd.arg("identity"), buf, len) >= 0
		&& buf[0] == '"') {
		pos = strchr(buf + 1, '"');
		if (pos)
			*pos = '\0';
		identityEdit->setText(buf + 1);
	}

	res = wpagui->ctrlRequest(cmd.arg("password"), buf, len);
	if (res >= 0 && buf[0] == '"') {
		pos = strchr(buf + 1, '"');
		if (pos)
			*pos = '\0';
		passwordEdit->setText(buf + 1);
	} else if (res >= 0) {
		passwordEdit->setText(WPA_GUI_KEY_DATA);
	}

	if (wpagui->ctrlRequest(cmd.arg("ca_cert"), buf, len) >= 0) {
		pos = strchr(buf + 1, '"');
		if (pos)
			*pos = '\0';
		cacertEdit->setText(buf + 1);
	}

	enum { NO_INNER, PEAP_INNER, TTLS_INNER, FAST_INNER } eap = NO_INNER;
	if (wpagui->ctrlRequest(cmd.arg("eap"), buf, len) >= 0) {
		for (i = 0; i < eapSelect->count(); i++) {
			if (eapSelect->itemText(i).compare(buf) == 0) {
				eapSelect->setCurrentIndex(i);
				if (strcmp(buf, "PEAP") == 0)
					eap = PEAP_INNER;
				else if (strcmp(buf, "TTLS") == 0)
					eap = TTLS_INNER;
				else if (strcmp(buf, "FAST") == 0)
					eap = FAST_INNER;
				break;
			}
		}
	}

	if (eap != NO_INNER) {
		if (wpagui->ctrlRequest(cmd.arg("phase2"), buf, len) >= 0) {
			eapChanged(eapSelect->currentIndex());
		} else
			eap = NO_INNER;
	}

	char *val;
	val = buf + 1;
	while (*(val + 1))
		val++;
	if (*val == '"')
		*val = '\0';

	switch (eap) {
	case PEAP_INNER:
		if (strncmp(buf, "\"auth=", 6))
			break;
		val = buf + 2;
		memcpy(val, "EAP-", 4);
		break;
	case TTLS_INNER:
		if (strncmp(buf, "\"autheap=", 9) == 0) {
			val = buf + 5;
			memcpy(val, "EAP-", 4);
		} else if (strncmp(buf, "\"auth=", 6) == 0)
			val = buf + 6;
		break;
	case FAST_INNER:
		if (strncmp(buf, "\"auth=", 6))
			break;
		if (strcmp(buf + 6, "GTC auth=MSCHAPV2") == 0) {
			val = (char *) "GTC(auth) + MSCHAPv2(prov)";
			break;
		}
		val = buf + 2;
		memcpy(val, "EAP-", 4);
		break;
	case NO_INNER:
		break;
	}

	for (i = 0; i < phase2Select->count(); i++) {
		if (phase2Select->itemText(i).compare(val) == 0) {
			phase2Select->setCurrentIndex(i);
			break;
		}
	}

	for (i = 0; i < 4; i++) {
		QLineEdit *wepEdit;
		switch (i) {
		default:
		case 0:
			wepEdit = wep0Edit;
			break;
		case 1:
			wepEdit = wep1Edit;
			break;
		case 2:
			wepEdit = wep2Edit;
			break;
		case 3:
			wepEdit = wep3Edit;
			break;
		}
		res = wpagui->ctrlRequest(cmd.arg("wep_key%1").arg(i), buf, len);
		if (res >= 0 && buf[0] == '"') {
			pos = strchr(buf + 1, '"');
			if (pos)
				*pos = '\0';
			if (auth == AUTH_NONE_OPEN || auth == AUTH_IEEE8021X) {
				if (auth == AUTH_NONE_OPEN)
					auth = AUTH_NONE_WEP;
				encr = 1;
			}

			wepEdit->setText(buf + 1);
		} else if (res >= 0) {
			if (auth == AUTH_NONE_OPEN || auth == AUTH_IEEE8021X) {
				if (auth == AUTH_NONE_OPEN)
					auth = AUTH_NONE_WEP;
				encr = 1;
			}
			wepEdit->setText(WPA_GUI_KEY_DATA);
		}
	}

	if (auth == AUTH_NONE_WEP) {
		if (wpagui->ctrlRequest(cmd.arg("auth_alg"), buf, len) >= 0) {
			if (strcmp(buf, "SHARED") == 0)
				auth = AUTH_NONE_WEP_SHARED;
		}
	}

	if (wpagui->ctrlRequest(cmd.arg("wep_tx_keyidx"), buf, len) >= 0)
	{
		switch (atoi(buf)) {
		case 0:
			wep0Radio->setChecked(true);
			break;
		case 1:
			wep1Radio->setChecked(true);
			break;
		case 2:
			wep2Radio->setChecked(true);
			break;
		case 3:
			wep3Radio->setChecked(true);
			break;
		}
	}
	if (wpagui->ctrlRequest(cmd.arg("id_str"), buf, len) >= 0) {
		pos = strchr(buf + 1, '"');
		if (pos)
			*pos = '\0';
		idstrEdit->setText(buf + 1);
	}

	if (wpagui->ctrlRequest(cmd.arg("priority"), buf, len) >= 0)
		prioritySpinBox->setValue(atoi(buf));

	authSelect->setCurrentIndex(auth);
	authChanged(auth);
	encrSelect->setCurrentIndex(encr);
	wepEnabled(auth == AUTH_NONE_WEP || auth == AUTH_NONE_WEP_SHARED);

	removeButton->setEnabled(true);
	addButton->setText(tr("Apply"));
	setWindowTitle(tr("Edit Network Block - %1").arg(network_id));
}


void NetworkConfig::removeNetwork()
{
	wpagui->removeNetwork(QString::number(edit_network_id));
	close();
}


void NetworkConfig::newNetwork()
{
	new_network = true;
	getEapCapa();
	// Trigger UI to collapse to only fitting options
	authChanged(0);
}


void NetworkConfig::getEapCapa()
{
	size_t len(256); char buf[len];

	if (wpagui == NULL)
		return;

	if (wpagui->ctrlRequest("GET_CAPABILITY eap", buf, len) < 0)
		return;

	QString res(buf);
	QStringList types = res.split(QChar(' '));
	eapSelect->insertItems(-1, types);
}


void NetworkConfig::useWps()
{
	if (wpagui == NULL)
		return;
	wpagui->setBssFromScan(bssid);
	wpagui->wpsDialog();
	close();
}

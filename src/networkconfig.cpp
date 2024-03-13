/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018, 2022, 2024 loh.tar@googlemail.com
 *
 * wpa_gui - NetworkConfig class
 * Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#include <cstdio>
#include <QMessageBox>

#include "about.h"
#include "networkconfig.h"
#include "scanresults.h"
#include "wpagui.h"

enum {
	AUTH_NONE_OPEN,
	AUTH_NONE_WEP,
	AUTH_NONE_WEP_SHARED,
	AUTH_IEEE8021X_WIRED,
	AUTH_IEEE8021X,
	AUTH_WPA_PSK,
	AUTH_WPA_EAP,
	AUTH_WPA2_PSK,
	AUTH_WPA2_EAP,
	AUTH_WPA2_OWE,
	AUTH_WPA2_SAE,
	AUTH_WPA3_EAP,
	AUTH_DEFAULTS
};

#define WPA_GUI_KEY_DATA "[key is configured]"
#define InQuotes true


NetworkConfig::NetworkConfig(WpaGui* parent)
             : QDialog(parent)
             , wpagui(parent) {

	setupUi(this);

	makeAvailable(encrBox, false);
	connect(applyBssidButton, SIGNAL(clicked())
	      , this, SLOT(pullTheAce()));
	connect(authSelect, SIGNAL(currentIndexChanged(int))
	      , this, SLOT(authChanged(int)));
	connect(cancelButton, SIGNAL(clicked())
	      , this, SLOT(close()));
	connect(addButton, SIGNAL(clicked())
	      , this, SLOT(applyNetworkChanges()));
	connect(removeButton, SIGNAL(clicked())
	     , this, SLOT(removeNetwork()));
	connect(eapSelect, SIGNAL(activated(int))
	      , this, SLOT(eapChanged(int)));

	QTimer::singleShot(100, [this]() {
		resize(sizeHint());
		adjustSize();
	});

}


NetworkConfig::~NetworkConfig() {

}


void NetworkConfig::languageChange() {

	retranslateUi(this);
}


void NetworkConfig::newNetwork(QTreeWidgetItem* sel) {

	/* SSID BSSID signal frequency flags */
	setWindowTitle(sel->text(ScanResults::SRColSsid));
	ssidEdit->setText(sel->text(ScanResults::SRColSsid));
	bssidEdit->setText(sel->text(ScanResults::SRColBssid));

	QString flags = sel->text(ScanResults::SRColFlags);
	int auth, encr = 0;
	if (flags.indexOf("[WPA2-EAP") >= 0)
		auth = AUTH_WPA2_EAP;
	else if (flags.indexOf("[WPA-EAP") >= 0)
		auth = AUTH_WPA_EAP;
	else if (flags.indexOf("[WPA2-OWE") >= 0)
		auth = AUTH_WPA2_OWE;
	else if (flags.indexOf("[WPA2-SAE") >= 0)
		auth = AUTH_WPA2_SAE;
	else if (flags.indexOf("[WPA2-PSK+SAE") >= 0)
		// FIXME ATM I like to keep it simple, not sure what we need all to do to offer
		// the option to use the insecure possibility the AP advertise
		// ==> just handle like WPA2-SAE only mode
		auth = AUTH_WPA2_SAE;
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

	newNetwork();

	authSelect->setCurrentIndex(auth);
	encrSelect->setCurrentIndex(encr);
}


void NetworkConfig::makeAvailable(QWidget* w, const bool yes) {

	w->setVisible(yes);
	w->setEnabled(yes);
}


void NetworkConfig::authChanged(int sel) {

	makeAvailable(keyMgtBox, sel != AUTH_NONE_OPEN && sel != AUTH_NONE_WEP && sel != AUTH_NONE_WEP_SHARED && sel != AUTH_WPA2_OWE);
	makeAvailable(encrBox, sel != AUTH_NONE_OPEN && sel != AUTH_NONE_WEP && sel != AUTH_NONE_WEP_SHARED && sel != AUTH_IEEE8021X && sel != AUTH_WPA2_OWE);
	makeAvailable(pskBox, sel == AUTH_WPA_PSK || sel == AUTH_WPA2_PSK || sel == AUTH_DEFAULTS);
	makeAvailable(saeBox, sel == AUTH_WPA2_SAE || sel == AUTH_WPA3_EAP);
	makeAvailable(eapBox, sel == AUTH_IEEE8021X || sel == AUTH_WPA_EAP || sel == AUTH_WPA2_EAP || sel == AUTH_WPA3_EAP);

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

	// Wow, that was a hard lesson!
	// Thanks to Cerno/Daniel https://stackoverflow.com/a/1679399
	QApplication::processEvents();
	resize(sizeHint());
	adjustSize();
}


void NetworkConfig::eapChanged(int sel) {

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


void NetworkConfig::applyNetworkChanges() {

	size_t len(10); char buf[len];
	QString id;
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
		QRegularExpression rx("^(\\w|-)+$");
		if (rx.match(idstrEdit->text()).lastCapturedIndex() < 0) {
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

	if (bssidEdit->text().isEmpty()) {
		bssidEdit->setText("any");
	} else if (!QRegularExpression("([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})").match(bssidEdit->text()).hasMatch()) {
		// Thanks to https://stackoverflow.com/a/4260512
		QMessageBox::warning(this, tr("Not a valid BSSID")
			, tr("The BSSID must consist of 12 hex digits "
			      "separated by colons, like:\n\n\t 12:34:56:78:9a:bc"));
		bssidEdit->setFocus();
		return;
	}

	if (wpagui == NULL)
		return;

	memset(buf, 0, sizeof(buf));

	// To ensure we save no old configured stuff in our modified network block we
	// perform a "remove-old and add-new" operation. It pointed out, that wpa_supplicant
	// behaves not logical (in my opinion) when we try to remove a not wanted setting
	// from the network. I would expect that calling "SET_NETWORK foo NULL" would do it, but nope!
	// Sometimes he reject this with an error and "foo=bar" is still there

	if (wpagui->ctrlRequest("ADD_NETWORK", buf, len) < 0) {
		QMessageBox::warning(this, ProjAppName,
								tr("Failed to add new network to \n"
								"wpa_supplicant configuration."));
		return;
	}
	id = buf;
	id.remove('\n');

	newNetworkId = id;

	setNetworkParam(id, "ssid", ssidEdit->text(), InQuotes);
	setNetworkParam(id, "bssid", bssidEdit->text());
	setNetworkParam(id, "priority", prioritySpinBox->cleanText());
	setNetworkParam(id, "id_str", idstrEdit->text(), InQuotes);

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
	case AUTH_WPA2_OWE:
		key_mgmt = "OWE";
		proto = "RSN";
		pairwise = "CCMP";
		setNetworkParam(id, "ieee80211w", "2");
		break;
	case AUTH_WPA2_SAE:
		key_mgmt = "SAE";
		proto = "RSN";
		break;

	}

	if (auth == AUTH_NONE_WEP_SHARED)
		setNetworkParam(id, "auth_alg", "SHARED");
	else
		setNetworkParam(id, "auth_alg", "OPEN");

	if (encrBox->isEnabled()) {
		int encr = encrSelect->currentIndex();
		if (encr == 0)
			pairwise = "TKIP";
		else
			pairwise = "CCMP";
	}

	setNetworkParam(id, "proto", proto);
	setNetworkParam(id, "key_mgmt", key_mgmt);
	setNetworkParam(id, "pairwise", pairwise);

	if (pskBox->isEnabled()) {
		if (pskEdit->text() != WPA_GUI_KEY_DATA) {
			setNetworkParam(id, "psk", pskEdit->text(), psklen != 64);
		} else {
			copyNetworkParam("psk");
		}
	}

	if (saeBox->isEnabled()) {
		if (saeEdit->text() != WPA_GUI_KEY_DATA) {
			setNetworkParam(id, "sae_password", saeEdit->text(), InQuotes);
		} else {
			copyNetworkParam("sae_password");
		}
		setNetworkParam(id, "ieee80211w", "2");
	}

	if (eapBox->isEnabled()) {
		QString eap = eapSelect->currentText();
		setNetworkParam(id, "eap", eap);
		// FIXME These two actions are looking questionable
		if ("SIM" == eap || "AKA" == eap)
			setNetworkParam(id, "pcsc", "", InQuotes);

		QString inner = phase2Select->currentText();
		QString phase2;
		if (eap.compare("PEAP") == 0) {
			if (inner.startsWith("EAP-")) {
				phase2 = QString("auth=%1").arg(inner.right(inner.size() - 4));
			}
		} else if (eap.compare("TTLS") == 0) {
			if (inner.startsWith("EAP-")) {
				phase2 = QString("autheap=%1").arg(inner.right(inner.size() - 4));
			}
			else {
				phase2 = QString("auth=%1").arg(inner);
			}
		} else if (eap.compare("FAST") == 0) {
			const char *provisioning = NULL;
			if (inner.startsWith("EAP-")) {
				phase2 = QString("auth=%1").arg(inner.right(inner.size() - 4));
				provisioning = "fast_provisioning=2";
			} else if (inner.compare("GTC(auth) + MSCHAPv2(prov)") == 0) {
				phase2 = "auth=GTC auth=MSCHAPV2";
				provisioning = "fast_provisioning=1";
			} else
				provisioning = "fast_provisioning=3";

			if (provisioning) {
				setNetworkParam(id, "phase1", provisioning, InQuotes);
				setNetworkParam(id, "pac_file"
				              , QString("blob://fast-pac-%1").arg(id)
				              , InQuotes);
			}
		}

		if (passwordEdit->text() != WPA_GUI_KEY_DATA) {
			setNetworkParam(id, "password", passwordEdit->text(), InQuotes);
		}else {
			copyNetworkParam("password");
		}

		setNetworkParam(id, "phase2", phase2, InQuotes);
		setNetworkParam(id, "identity", identityEdit->text(), InQuotes);
		setNetworkParam(id, "ca_cert", cacertEdit->text(), InQuotes);
	}


	// WEP stuff, to be removed!
	writeWepKey(id, wep0Edit, 0);
	writeWepKey(id, wep1Edit, 1);
	writeWepKey(id, wep2Edit, 2);
	writeWepKey(id, wep3Edit, 3);

	if (wep0Radio->isEnabled() && wep0Radio->isChecked())
		setNetworkParam(id, "wep_tx_keyidx", "0");
	else if (wep1Radio->isEnabled() && wep1Radio->isChecked())
		setNetworkParam(id, "wep_tx_keyidx", "1");
	else if (wep2Radio->isEnabled() && wep2Radio->isChecked())
		setNetworkParam(id, "wep_tx_keyidx", "2");
	else if (wep3Radio->isEnabled() && wep3Radio->isChecked())
		setNetworkParam(id, "wep_tx_keyidx", "3");

	// Don't forget to delete the old/original network
	removeNetwork();
}


int NetworkConfig::setNetworkParam(const QString& id, const QString& parm,
                                   const QString& val, bool quote/* = false*/) {

	QString cmd;

	if (val.isEmpty()) return 0;

	if (quote)
		cmd = "SET_NETWORK %1 %2 \"%3\"";
	else
		cmd = "SET_NETWORK %1 %2 %3";

	return wpagui->ctrlRequest(cmd.arg(id).arg(parm).arg(val));
}


int NetworkConfig::copyNetworkParam(const QString& parm) {

	const QString cmd("DUP_NETWORK %1 %2 %3");
	return wpagui->ctrlRequest(cmd.arg(networkId).arg(newNetworkId).arg(parm));
}


void NetworkConfig::wepEnabled(bool enabled) {

	makeAvailable(wepBox, enabled);

	wep0Edit->setEnabled(enabled);
	wep1Edit->setEnabled(enabled);
	wep2Edit->setEnabled(enabled);
	wep3Edit->setEnabled(enabled);

	wep0Radio->setEnabled(enabled);
	wep1Radio->setEnabled(enabled);
	wep2Radio->setEnabled(enabled);
	wep3Radio->setEnabled(enabled);
}


void NetworkConfig::writeWepKey(const QString& id, QLineEdit* edit, int keyId) {

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
	hex = val.contains(QRegularExpression("^[0-9A-F]+$"));

	if (hex && len != 10 && len != 26 && len != 32)
		hex = false;
	QString var("wep_key%1");
	setNetworkParam(id, var.arg(keyId), val, !hex);
}


void NetworkConfig::pullTheAce() {

	bssidEdit->setText(aceInTheHoleId);
}


void NetworkConfig::editNetwork(const QString& id, const QString& bssid/* = ""*/) {

	int i, res;

	networkId = id;
	getEapCapa();

	size_t len(1024); char buf[len];
	char *pos;
	QString cmd("GET_NETWORK %1 %2");
	cmd = cmd.arg(id);

	if (wpagui->ctrlRequest(cmd.arg("ssid"), buf, len) >= 0) {
		pos = strchr(buf + 1, '"');
		if (pos)
			*pos = '\0';
		ssidEdit->setText(buf + 1);
	}

	if (wpagui->ctrlRequest(cmd.arg("bssid"), buf, len) >= 0) {
		bssidEdit->setText(buf);
		aceInTheHoleId = buf;
	} else if (!bssid.isEmpty()) {
		aceInTheHoleId = bssid;
	}
	if (!aceInTheHoleId.isEmpty()) {
		applyBssidButton->setToolTip(tr("Apply BSSID to %1").arg(bssid));
		applyBssidButton->setEnabled(true);
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
		keyMgtSelect->setCurrentText(buf);
		if (strstr(buf, "WPA-PSK WPA-EAP")) {
			auth = AUTH_DEFAULTS;
			encr = 1;
		}
		else if (strstr(buf, "WPA-EAP"))
			auth = wpa & 2 ? AUTH_WPA2_EAP : AUTH_WPA_EAP;
		else if (strstr(buf, "WPA-PSK"))
			auth = wpa & 2 ? AUTH_WPA2_PSK : AUTH_WPA_PSK;
		else if (strstr(buf, "OWE"))
			auth = AUTH_WPA2_OWE;
		else if (strstr(buf, "SAE")) {
			auth = AUTH_WPA2_SAE;
			encr = 1;
		}
		else if (strstr(buf, "IEEE8021X")) {
			auth = AUTH_IEEE8021X;
			encr = 1;
		}
	}

	if (wpagui->ctrlRequest(cmd.arg("pairwise"), buf, len) >= 0) {
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

	res = wpagui->ctrlRequest(cmd.arg("sae_password"), buf, len);
	if (res >= 0 && buf[0] == '"') {
		pos = strchr(buf + 1, '"');
		if (pos)
			*pos = '\0';
		saeEdit->setText(buf + 1);
	} else if (res >= 0) {
		saeEdit->setText(WPA_GUI_KEY_DATA);
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
		QLineEdit* wepEdit;
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
	// Ensure UI will collapse to only fitting options
	// when these has not cause a change signal
	authChanged(auth);
	encrSelect->setCurrentIndex(encr);

	removeButton->setEnabled(true);
	addButton->setText(tr("Apply"));
	setWindowTitle(tr("Edit Network Block - %1").arg(id));
}


void NetworkConfig::removeNetwork() {

	wpagui->removeNetwork(networkId);
	close();
}


void NetworkConfig::newNetwork() {

	getEapCapa();
	// Trigger UI to collapse to only fitting options
	authChanged(0);
}


void NetworkConfig::getEapCapa() {

	size_t len(256); char buf[len];

	if (wpagui == NULL)
		return;

	if (wpagui->ctrlRequest("GET_CAPABILITY eap", buf, len) < 0)
		return;

	QString res(buf);
	QStringList types = res.split(QChar(' '));
	eapSelect->insertItems(-1, types);
}

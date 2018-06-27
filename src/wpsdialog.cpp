/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018 loh.tar@googlemail.com
 *
 * Based on ideas by Jouni Malinen <j@w1.fi> and contributors
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */


#include "wpsdialog.h"

#include <QToolTip>

#include "wpagui.h"


WpsDialog::WpsDialog(WpaGui* _wpagui)
         : QDialog(0) // No parent so wpagui can above us
         , wpagui(_wpagui)
         , wpsPbcOverlap(false) {

	setupUi(this);
	setWindowIcon(wpagui->windowIcon()); // No parent, ensure we have the icon

	wpsMethodTab->setTabEnabled(wpsMethodTab->indexOf(useApPinTab), false);

	connect(wpsMethodTab, SIGNAL(currentChanged(int)), this, SLOT(tabChanged()));
	connect(wpsApPinEdit, SIGNAL(textChanged(const QString &)), this, SLOT(wpsApPinChanged(const QString &)));
	connect(wpsPbcButton, SIGNAL(clicked()), this, SLOT(wpsPbcButtonClicked()));
	connect(wpsApPinButton, SIGNAL(clicked()), this, SLOT(wpsApPinButtonClicked()));
	connect(wpsPinButton, SIGNAL(clicked()), this, SLOT(wpsPinButtonClicked()));
	connect(cancelButton, SIGNAL(clicked()), this, SLOT(reject()));
	connect(scanButton, SIGNAL(clicked()), wpagui, SLOT(showScanWindow()));

	wpsMethodTab->setCurrentWidget(hintTab);
}


WpsDialog::~WpsDialog() {
}


void WpsDialog::setNetworkIds(const QString& ssid, const QString& bssid) {

	textSsid->setText(ssid);
	textBssid->setText(bssid);
	wpsMethodTab->setTabEnabled(wpsMethodTab->indexOf(useApPinTab), true);
	wpsMethodTab->setTabEnabled(wpsMethodTab->indexOf(generatePinTab), true);
	wpsMethodTab->setTabEnabled(wpsMethodTab->indexOf(hintTab), false);

	wpsPinEdit->clear();
	wpsMethodTab->setCurrentWidget(pbcTab);
	tabChanged();  // Ensure instructions are updated
}


void WpsDialog::activePbcAvailable(const QString& _ssid/* = ""*/, const QString& _bssid/* = ""*/) {

	// I 'love it' to have the same/similar code at more than one place but have
	// now no idea for a nice looking solution -> copy&paste from scanresults
	size_t len(2048); char buf[len];
	const QString cmd("BSS %1");
	int index(0);
	QString ssid(_ssid), bssid(_bssid);

	if (!ssid.isEmpty() && !bssid.isEmpty())
		index = 1000;

	while (wpagui && index < 1000) {
		if (wpagui->ctrlRequest(cmd.arg(index++), buf, len) < 0)
			break;

		QString bss(buf);
		if (bss.isEmpty())
			break;

		if (!bss.contains("[WPS-PBC]"))
			continue;

		QString flags;

		QStringList lines = bss.split(QRegExp("\\n"));
		for (QStringList::Iterator it = lines.begin();
		     it != lines.end(); it++) {
			int pos = (*it).indexOf('=') + 1;
			if (pos < 1)
				continue;

			if ((*it).startsWith("bssid="))
				bssid = (*it).mid(pos);
			else if ((*it).startsWith("flags="))
				flags = (*it).mid(pos);
			else if ((*it).startsWith("ssid="))
				ssid = (*it).mid(pos);
		}

		// Just to be sure, test again
		if (!flags.contains("[WPS-PBC]"))
			continue;

		break;
	}

	textBssid->setText(bssid);
	textSsid->setText(ssid);

	wpsMethodTab->setTabEnabled(wpsMethodTab->indexOf(useApPinTab), false);
	wpsMethodTab->setTabEnabled(wpsMethodTab->indexOf(generatePinTab), false);
	wpsMethodTab->setTabEnabled(wpsMethodTab->indexOf(hintTab), false);
	wpsMethodTab->setCurrentWidget(pbcTab);
	QString btnTxt = wpsPbcButton->text();
	btnTxt = btnTxt.remove('&');
	wpsInstructions->setText(tr(
		"Click the '%1' button to connect to waiting AP %2.").arg(btnTxt).arg(ssid));
	activateWindow();
}


void WpsDialog::pbcOverlapDetected() {

	wpsPbcOverlap = true;
	wpsMethodTab->setTabEnabled(wpsMethodTab->indexOf(hintTab), true);
	wpsMethodTab->setCurrentWidget(hintTab);
	tabChanged();
	show();
}


void WpsDialog::reject() {

	wpagui->wpsCancel();
	QDialog::reject();
}

void WpsDialog::languageChange() {

	retranslateUi(this);
}


void WpsDialog::tabChanged() {

	QString btnTxt;

	if (wpsMethodTab->currentWidget() == pbcTab) {
		// To do things 'right' is often unnecessarily difficult
		btnTxt = wpsPbcButton->text();
		// Yeah, here my patience ended, no consideration of &&
		btnTxt = btnTxt.remove('&');
		wpsInstructions->setText(tr(
			"To use the 'Push Button Configuration' method click the '%1' button "
			"and do the same on the AP, where it usualy labeled is 'WPS'.")
			.arg(btnTxt));
	} else if (wpsMethodTab->currentWidget() == useApPinTab) {
		btnTxt = wpsApPinButton->text();
		btnTxt = btnTxt.remove('&');
		wpsInstructions->setText(tr(
			"If you want to use an AP device PIN, e.g., from a label in the "
			"device, enter the eight digit AP PIN and click the '%1' button.")
			.arg(btnTxt));
	} else if (wpsMethodTab->currentWidget() == generatePinTab) {
		btnTxt = wpsPinButton->text();
		btnTxt = btnTxt.remove('&');
		wpsInstructions->setText(tr(
			"Click the '%1' button and then enter the shown PIN into the Registrar.\n\n"
			"The Registrar is usualy an internal one in the AP but could also be an external one.")
			.arg(btnTxt));
	} else if (wpsMethodTab->currentWidget() == hintTab) {
		if (wpsPbcOverlap) {
			wpsInstructions->setText(tr(
				"More than one AP is currently in active WPS PBC mode.\n\n"
				"Wait a couple of minutes and try again."));
		} else {
			btnTxt = scanButton->text();
			btnTxt = btnTxt.remove('&');
			wpsInstructions->setText(tr(
				"To enable the grayed tab choose the target network from the Scan window.\n\n"
				"It may general recommend to do so when using any kind of WPS setup, "
				"just to be sure who answers to the offer.\n\n"
				"So click the '%1' button here and the 'WPS Connect' button there.")
				.arg(btnTxt));
		}
	}
}


void WpsDialog::wpsApPinChanged(const QString &text) {

	wpsApPinButton->setEnabled(false);

	if (text.length() == 8) {
		if (wpagui->ctrlRequest("WPS_CHECK_PIN " + text))
			QToolTip::showText(wpsApPinEdit->mapToGlobal(QPoint(10, 20)), tr("PIN is not valid"));
		else
			wpsApPinButton->setEnabled(true);
	}
}


void WpsDialog::wpsPbcButtonClicked() {

	wpsPbcOverlap = false;
	wpagui->wpsPbc(textBssid->text());
	accept();
	wpagui->activateWindow();
}


void WpsDialog::wpsApPinButtonClicked() {

	wpagui->wpsApPin(textBssid->text(), wpsApPinEdit->text());
	accept();
	wpagui->activateWindow();
}


void WpsDialog::wpsPinButtonClicked() {

	QString pin = wpagui->wpsGeneratePin(textBssid->text());
	wpsPinEdit->setText(pin);

	QString btnTxt = cancelButton->text();
	btnTxt = btnTxt.remove('&');
	wpsInstructions->setText(tr(
		"The WPS procedures is running.\n\n"
		"Enter the shown PIN into the Registrar or click '%1' to abbort.")
		.arg(btnTxt));
}


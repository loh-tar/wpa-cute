/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018, 2022 loh.tar@googlemail.com
 *
 * wpa_gui - ScanResults class
 * Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#include "scanresults.h"

#include "networkconfig.h"
#include "scanresultsitem.h"
#include "signalbar.h"
#include "wpagui.h"
#include "wpsdialog.h"


ScanResults::ScanResults(WpaGui* _wpagui)
           : QDialog(0) // No parent so wpagui can above us
           , wpagui(_wpagui)
           , selectedNetwork(nullptr) {

	setupUi(this);

	connect(closeButton, SIGNAL(clicked()), this, SLOT(close()));
	connect(scanButton, SIGNAL(clicked()), this, SLOT(requestScan()));
	connect(chooseButton, SIGNAL(clicked()), this, SLOT(chooseNetwork()));
	connect(addButton, SIGNAL(clicked()), this, SLOT(addNetwork()));
	connect(wpsButton, SIGNAL(clicked()), this, SLOT(showWpsDialog()));

	connect(scanResultsWidget, SIGNAL(currentItemChanged(QTreeWidgetItem*, QTreeWidgetItem*))
	      , this, SLOT(networkSelected(QTreeWidgetItem*)));
	connect(scanResultsWidget, SIGNAL(itemDoubleClicked(QTreeWidgetItem*, int))
          , this, SLOT(addNetwork()));

	scanResultsWidget->setItemsExpandable(false);
	scanResultsWidget->setRootIsDecorated(false);
	scanResultsWidget->setItemDelegate(new SignalBar(scanResultsWidget));

	// FIXME When wpagui has some func to check tally, use tally instead
	size_t len(100); char buf[len];
	wpagui->ctrlRequest("GET_CAPABILITY eap", buf, len);
	wpsIsSupported = QString(buf).split(' ').contains("WSC");

	// No parent, ensure we have the icon
	setWindowIcon(wpagui->windowIcon());

	updateResults();

	if (scanResultsWidget->topLevelItemCount() < 2)
		requestScan();
}


ScanResults::~ScanResults() {
}


void ScanResults::languageChange() {

	retranslateUi(this);
}


void ScanResults::requestScan() {

	scanButton->setEnabled(false);
	wpagui->scan4Networks();
}


void ScanResults::updateResults() {

	size_t len(2048); char buf[len];
	int index(0);
	const QString cmd("BSS %1");
	QList<int> ssidTextWidth;

	QString selectedBSSID;
	if (selectedNetwork)
		selectedBSSID = selectedNetwork->text(SRColBssid);

	selectedNetwork = nullptr;
	scanResultsWidget->clear();

	// The wpa_supplicant does sadly not deliver information about which
	// scanned network he (probably) knows, so we have to puzzle it out
	QHash<QString, QString> idBySSID;   // SSID/id
	QHash<QString, QString> idByBSSID;  // BSSID/id
	QHash<QString, QString> knownNet;   // BSSID/SSID
	QSet<QString> lookalike;            // To note that idBySSID is not unique
	QSet<QString> wrongKey;
	QSet<QString> usedCandidate;
	QString currentBSSID;
	QTreeWidgetItem* currentNetwork(nullptr);
	QTreeWidgetItem* wrongKeyOption(nullptr);
	QTreeWidgetItem* bestAltOption(nullptr);
	QString currentId;
	for (int i = 0; i < wpagui->networkList->topLevelItemCount(); i++) {
		QTreeWidgetItem* item = wpagui->networkList->topLevelItem(i);
		const QString id    = item->text(WpaGui::NLColId);
		const QString ssid  = item->text(WpaGui::NLColSsid);
		const QString bssid = item->text(WpaGui::NLColBssid);
		if (item->text(WpaGui::NLColFlags).contains("[CURRENT]")) {
			currentBSSID = wpagui->textBssid->text();
			currentId    = id;
			continue;
		}
		if (item->text(WpaGui::NLColFlags).contains("[TEMP-DISABLED]")) {
			wrongKey.insert(id);
		}
		if (!bssid.compare("any", Qt::CaseInsensitive) == 0) {
			knownNet.insert(bssid, ssid);
			idByBSSID.insert(bssid, id);
			continue;
		}
		if (idBySSID.contains(ssid)) {
			lookalike.insert(ssid);
		} else {
			idBySSID.insert(ssid, id);
		}
	}

	while (wpagui && index < 1000) {
		if (wpagui->ctrlRequest(cmd.arg(index++), buf, len) < 0)
			break;

		QString bss(buf);
		if (bss.isEmpty())
			break;

		QString ssid, bssid, freq, signal, flags, customFlags;

		QStringList lines = bss.split(QLatin1Char('\n'));
		for (QStringList::Iterator it = lines.begin();
		     it != lines.end(); it++) {
			int pos = (*it).indexOf('=') + 1;
			if (pos < 1)
				continue;

			if ((*it).startsWith("bssid="))
				bssid = (*it).mid(pos);
			else if ((*it).startsWith("freq="))
				freq = (*it).mid(pos);
			else if ((*it).startsWith("level="))
				signal = (*it).mid(pos);
			else if ((*it).startsWith("flags="))
				flags = (*it).mid(pos);
			else if ((*it).startsWith("ssid="))
				ssid = (*it).mid(pos);
		}

		ssidTextWidth << scanResultsWidget->fontMetrics().horizontalAdvance(ssid);

		ScanResultsItem *item = new ScanResultsItem(scanResultsWidget);
		if (item) {
			item->setText(SRColSsid, ssid);
			item->setText(SRColBssid, bssid);
			item->setText(SRColSignal, signal);
			item->setText(SRColFreq, freq);
			QString wrongKeyId = "not-set";
			if (currentBSSID == bssid) {
				customFlags = QString("[CURRENT-%1]").arg(currentId);
				customFlags.append(wpagui->getIdFlag(currentId));
				currentNetwork = item;
				wrongKeyId = currentId;
			} else if (knownNet.contains(bssid) && knownNet.value(bssid) == ssid) {
				customFlags = QString("[KNOWN-%1]").arg(idByBSSID.value(bssid));
				customFlags.append(wpagui->getIdFlag(idByBSSID.value(bssid)));
				bestAltOption = item;
				wrongKeyId = idByBSSID.value(bssid);
			} else if (lookalike.contains(ssid)) {
				customFlags = "[CANDIDATE]";
				bestAltOption = item;
			} else if (idBySSID.contains(ssid)) {
				customFlags = QString("[CANDIDATE-%1]").arg(idBySSID.value(ssid));
				customFlags.append(wpagui->getIdFlag(idBySSID.value(ssid)));
				if (usedCandidate.contains(customFlags)) {
					foreach(QTreeWidgetItem* item, scanResultsWidget->findItems(customFlags, Qt::MatchContains, SRColFlags)) {
						QString txt = item->text(SRColFlags).replace(customFlags, "[CANDIDATE]");
						txt = item->text(SRColFlags).remove("[WRONG-KEY]");
						item->setText(SRColFlags, txt);
					}
					lookalike.insert(ssid);
					customFlags = "[CANDIDATE]";
				} else {
					usedCandidate.insert(customFlags);
					wrongKeyId = idBySSID.value(ssid);
				}
				bestAltOption = item;
			}

			if (wrongKey.contains(wrongKeyId))
				customFlags.append("[WRONG-KEY]");

			if (!customFlags.isEmpty())
				customFlags.prepend("* ");

			flags.prepend(customFlags);
			item->setText(SRColFlags, flags);

			if (selectedBSSID == bssid)
				selectedNetwork = item;
		}
		if (bssid.isEmpty())
			break;
	}

	// Because the result of this resizing...
	for (int i = 0; i < scanResultsWidget->columnCount(); ++i)
		scanResultsWidget->resizeColumnToContents(i);

	// ...looks for me not so charming, I do some effort to pleasure my eyes
	// WTF!? qSort is deprecated
	std::sort(ssidTextWidth.begin(), ssidTextWidth.end());
	QHeaderView* h = scanResultsWidget->header();
	int idx(0);
	if (!ssidTextWidth.size())
		ssidTextWidth << h->defaultSectionSize();
	else
		idx = std::max(0, static_cast<int>(85 * ssidTextWidth.size() / 100) -1 );

	h->resizeSection(0, ssidTextWidth.at(idx));        // SSID

	h->setSectionResizeMode(2 , QHeaderView::Stretch); // Signal Bar

	scanButton->setEnabled(true);
	addButton->setEnabled(false);
	wpsButton->setEnabled(false);

	if (selectedNetwork)
		scanResultsWidget->setCurrentItem(selectedNetwork);
	else if (currentNetwork)
		scanResultsWidget->setCurrentItem(currentNetwork);
	else if (wrongKeyOption)
		scanResultsWidget->setCurrentItem(wrongKeyOption);
	else if (bestAltOption)
		scanResultsWidget->setCurrentItem(bestAltOption);
}


void ScanResults::networkSelected(QTreeWidgetItem* curr) {

	if (!curr)
		return;

	selectedNetwork = curr;

	QString flags = curr->text(SRColFlags);

	chooseButton->setEnabled(false);
	wpsButton->setEnabled(wpsIsSupported);
	addButton->setEnabled(true);
	addButton->setText(tr("Add Network"));
	selectedNetworkId.clear();
	QStringList testFlags = {"[CURRENT-", "[KNOWN-", "[CANDIDATE-"};
	foreach(const QString flag, testFlags) {
		if (!flags.contains(flag))
			continue;

		selectedNetworkId = flags.section(flag, 1, 1);
		selectedNetworkId = selectedNetworkId.section(']', 0, 0);

		addButton->setText(tr("Edit Network"));
		wpsButton->setEnabled(false);
		wpsButton->setEnabled(flags.contains("[WRONG-KEY]"));
		break;
	}

	if (!selectedNetworkId.isEmpty() && !flags.contains("[CURRENT-"))
		// Ignore [WRONG-KEY], who knows, perhapse a false info
		chooseButton->setEnabled(true);

	if (!flags.contains("[WPS"))
		wpsButton->setEnabled(false);

	if (flags.contains("[CANDIDATE]"))
		addButton->setEnabled(false);
}


void ScanResults::addNetwork() {

	if (!addButton->isEnabled())
		return;

	NetworkConfig nc(wpagui);

	if (selectedNetworkId.isEmpty()) {
		nc.newNetwork(selectedNetwork);
	} else {
		nc.editNetwork(selectedNetworkId, selectedNetwork->text(SRColBssid));
	}

	nc.exec();

	raise();
}


void ScanResults::showWpsDialog() {

	const QString ssid  = selectedNetwork->text(SRColSsid);
	const QString bssid = selectedNetwork->text(SRColBssid);

	wpagui->showWpsWindow();

	if (selectedNetwork->text(SRColFlags).contains("[WPS-PBC]"))
		wpagui->wpsWindow->activePbcAvailable(ssid, bssid);
	else
		wpagui->wpsWindow->setNetworkIds(ssid, bssid);
}


void ScanResults::chooseNetwork() {

	wpagui->chooseNetwork(selectedNetworkId, selectedNetwork->text(SRColSsid));
}

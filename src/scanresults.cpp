/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018 loh.tar@googlemail.com
 *
 * wpa_gui - ScanResults class
 * Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#include <cstdio>
#include <algorithm>

#include "scanresults.h"
#include "signalbar.h"
#include "wpagui.h"
#include "networkconfig.h"
#include "scanresultsitem.h"

ScanResults::ScanResults(WpaGui *_wpagui)
           : QDialog(0) // No parent so wpagui can above us
           , wpagui(_wpagui)
{
	setupUi(this);

	connect(closeButton, SIGNAL(clicked()), this, SLOT(close()));
	connect(scanButton, SIGNAL(clicked()), this, SLOT(requestScan()));
	connect(scanResultsWidget, SIGNAL(itemDoubleClicked(QTreeWidgetItem *, int))
	      , this, SLOT(bssSelected(QTreeWidgetItem *)));

	scanResultsWidget->setItemsExpandable(false);
	scanResultsWidget->setRootIsDecorated(false);
	scanResultsWidget->setItemDelegate(new SignalBar(scanResultsWidget));

	// No parent, ensure we have the icon
	setWindowIcon(wpagui->windowIcon());

	updateResults();

	if (scanResultsWidget->topLevelItemCount() < 2)
		requestScan();
}


ScanResults::~ScanResults()
{
}


void ScanResults::languageChange()
{
	retranslateUi(this);
}


void ScanResults::updateResults()
{
	size_t len(2048); char buf[len];
	int index(0);
	QString cmd("BSS %1");
	QList<int> ssidTextWidth;

	scanResultsWidget->clear();

	while (wpagui && index < 1000) {
		if (wpagui->ctrlRequest(cmd.arg(index++), buf, len) < 0)
			break;

		QString bss(buf);
		if (bss.isEmpty())
			break;

		QString ssid, bssid, freq, signal, flags;

		QStringList lines = bss.split(QRegExp("\\n"));
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

		ssidTextWidth << scanResultsWidget->fontMetrics().width(ssid);

		ScanResultsItem *item = new ScanResultsItem(scanResultsWidget);
		if (item) {
			item->setText(0, ssid);
			item->setText(1, bssid);
			item->setText(2, signal);
			item->setText(3, freq);
			item->setText(4, flags);
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
		idx = std::max(0, (85 * ssidTextWidth.size() / 100) -1 );

	h->resizeSection(0, ssidTextWidth.at(idx));        // SSID

	h->setSectionResizeMode(2 , QHeaderView::Stretch); // Signal Bar
}


void ScanResults::requestScan()
{
	if (wpagui == NULL)
		return;

	wpagui->ctrlRequest("SCAN");
}


void ScanResults::getResults()
{
	updateResults();
}


void ScanResults::bssSelected(QTreeWidgetItem *sel)
{
	NetworkConfig nc(wpagui);
	nc.paramsFromScanResults(sel);
	nc.exec();
}

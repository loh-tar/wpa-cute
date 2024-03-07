/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018, 2022, 2024 loh.tar@googlemail.com
 *
 * wpa_gui - ScanResultsItem class
 * Copyright (c) 2015, Adrian Nowicki <adinowicki@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#ifndef SCANRESULTSITEM_H
#define SCANRESULTSITEM_H

#include <QTreeWidgetItem>

class ScanResultsItem : public QTreeWidgetItem
{
public:
	ScanResultsItem(QTreeWidget* tree) : QTreeWidgetItem(tree) {}
	bool operator< (const QTreeWidgetItem &other) const;
};

#endif /* SCANRESULTSITEM_H */

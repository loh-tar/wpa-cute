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

#include "scanresultsitem.h"

bool ScanResultsItem::operator< (const QTreeWidgetItem &other) const {

	int sortCol = treeWidget()->sortColumn();
	if (sortCol == 3) {
		return text(sortCol).toInt() < other.text(sortCol).toInt();
	} else if (sortCol == 2) {
		return text(sortCol) > other.text(sortCol);
	}

	return text(sortCol) < other.text(sortCol);
}

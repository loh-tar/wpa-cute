/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018, 2022 loh.tar@googlemail.com
 *
 * wpa_gui - EventHistory class
 * Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#include <QScrollBar>

#include "eventhistory.h"


int EventListModel::rowCount(const QModelIndex& ) const {

	return msgList.count();
}


int EventListModel::columnCount(const QModelIndex& ) const {

	return 2;
}


QVariant EventListModel::data(const QModelIndex& index, int role) const {

	if (!index.isValid())
		return QVariant();

        if (role == Qt::DisplayRole)
		if (index.column() == 0) {
			if (index.row() >= timeList.size())
				return QVariant();
			return timeList.at(index.row());
		} else {
			if (index.row() >= msgList.size())
				return QVariant();
			return msgList.at(index.row());
		}
        else
		return QVariant();
}


QVariant EventListModel::headerData(int section, Qt::Orientation o, int role) const {

	if (role != Qt::DisplayRole)
		return QVariant();

	if (o == Qt::Horizontal) {
		switch (section) {
		case 0:
			return QString(tr("Timestamp"));
		case 1:
			return QString(tr("Message"));
		default:
			return QVariant();
		}
	} else
		return QString("%1").arg(section);
}


void EventListModel::addEvent(QString time, QString msg) {

	beginInsertRows(QModelIndex(), msgList.size(), msgList.size() + 1);
	timeList << time;
	msgList << msg;
	endInsertRows();
}


EventHistory::EventHistory(QWidget*  widget)
            : QDialog(0) // No parent so wpagui can above us
{
	setupUi(this);

	connect(closeButton, SIGNAL(clicked()), this, SLOT(close()));

	elm = new EventListModel(this);
	eventListView->setModel(elm);

	// No parent, ensure we have the icon
	setWindowIcon(widget->windowIcon());
}


EventHistory::~EventHistory() {
}


void EventHistory::languageChange() {

	retranslateUi(this);
}


void EventHistory::addEvents(WpaMsgList msgs) {

	WpaMsgList::iterator it;
	for (it = msgs.begin(); it != msgs.end(); it++)
		addEvent(*it);
}


void EventHistory::addEvent(WpaMsg msg) {

	bool scroll = true;

	if (eventListView->verticalScrollBar()->value() <
	    eventListView->verticalScrollBar()->maximum())
	    	scroll = false;

	elm->addEvent(msg.getTimestamp().toString("yyyy-MM-dd hh:mm:ss.zzz"),
		      msg.getMsg());

	if (scroll)
		eventListView->scrollToBottom();
}

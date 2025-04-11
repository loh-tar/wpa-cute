/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018, 2022, 2024, 2025 loh.tar@googlemail.com
 *
 * wpa_gui - EventHistory class
 * Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#ifndef EVENTHISTORY_H
#define EVENTHISTORY_H

#include <QObject>
#include "ui_eventhistory.h"


class EventListModel : public QAbstractTableModel
{
	Q_OBJECT

public:
	EventListModel(QObject* parent)	: QAbstractTableModel(parent) {};

	         int rowCount(const QModelIndex& parent = QModelIndex()) const;
	         int columnCount(const QModelIndex& parent = QModelIndex()) const;
	    QVariant data(const QModelIndex& index, int role) const;
	    QVariant headerData(int section, Qt::Orientation o, int role = Qt::DisplayRole) const;
	        void addEvent(QString time, QString msg);

private:
	 QStringList timeList;
	 QStringList msgList;
};


class EventHistory : public QDialog, public Ui::EventHistory
{
	Q_OBJECT

public:
	 EventHistory(QWidget* widget);
	~EventHistory();

public slots:
	        void addEvents(WpaMsgList msgs);
	        void addEvent(WpaMsg msg);

protected slots:
	        void languageChange();

private:
	EventListModel* elm;
};

#endif /* EVENTHISTORY_H */

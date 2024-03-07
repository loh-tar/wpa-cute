/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018, 2022, 2024 loh.tar@googlemail.com
 *
 * wpa_gui - SignalBar class
 * Copyright (c) 2011, Kel Modderman <kel@otaku42.de>
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#ifndef SIGNALBAR_H
#define SIGNALBAR_H

#include <QObject>
#include <QStyledItemDelegate>

class SignalBar : public QStyledItemDelegate
{
	Q_OBJECT

public:
	SignalBar(QObject* parent);
	~SignalBar();

	void paint(QPainter* painter
	         , const QStyleOptionViewItem& option
	         , const QModelIndex& index) const ;
};

#endif /* SIGNALBAR_H */

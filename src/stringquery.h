/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018, 2022, 2024, 2025 loh.tar@googlemail.com
 *
 * wpa_gui - StringQuery class
 * Copyright (c) 2009, Atheros Communications
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#ifndef STRINGQUERY_H
#define STRINGQUERY_H

#include <QDialog>
#include <QLineEdit>


class StringQuery : public QDialog
{
	Q_OBJECT

public:
	StringQuery(QString label);
	QString get_string();

private:
	QLineEdit edit;
};

#endif /* STRINGQUERY_H */

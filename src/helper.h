/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018, 2022, 2024, 2025 loh.tar@googlemail.com
 *
 * Collection of Helper Functions
 * Copyright (C) 2024 loh.tar@googlemail.com
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#ifndef HELPER_H
#define HELPER_H

#include <QString>

namespace Helper {

	QString signalToHumanText(const QString& signal);
	QString signalToHumanText(int signal);

}

#endif /* HELPER_H */

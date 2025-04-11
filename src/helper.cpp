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

#include "helper.h"

QString Helper::signalToHumanText(const QString& signal) {

		const int s = signal.toInt();
		if (s < -87) {
			return signal + "dBm ☆☆☆☆☆";
		} else if (s < -80) {
			return signal + "dBm ★☆☆☆☆";
		} else if (s < -73) {
			return signal + "dBm ★★☆☆☆";
		} else if (s < -65) {
			return signal + "dBm ★★★☆☆";
		} else if (s < -58) {
			return signal + "dBm ★★★★☆";
		} else {
			return signal + "dBm ★★★★★";
		}
}


QString Helper::signalToHumanText(int signal) {

	return signalToHumanText(QString::number(signal));
}


/*
 * wpaCute - A graphical wpa_supplicant front end
 * Copyright (C) 2018, 2022, 2024 loh.tar@googlemail.com
 *
 * wpaCute - About data
 *
 * This software may be distributed under the terms of the BSD license.
 * See COPYING for more details.
 */

#include "about.h"

// Some translation by tr(), or better QT_TR_NOOP, are disabled because
// I'm not sure if it make sense to translate these.

QString About::slogan() {

	static const char* str = ProjAppName QT_TR_NOOP(" - A graphical wpa_supplicant front end");

	return QString(str);
}


QString About::copyright() {

	static const char* str = "%1\n"
	            "Copyright (C) 2018, 2022, 2024 loh.tar@googlemail.com"
	            "\n\n"
	            ProjAppName QT_TR_NOOP(" is a fork from wpa_gui shipped with \n"
	            "wpa_supplicant version 2.6")
	            "\n\n"
	            "wpa_gui for wpa_supplicant\n"
	            "Copyright (C) 2005-2015 Jouni Malinen <j@w1.fi> \n"
	            "and contributors";

	return QString(str).arg(slogan());
}


QString About::text(const QString& see) {

	static const char* str = "%1" QT_TR_NOOP("\n\n"
	            "This software may be distributed under\n"
	            "the terms of the BSD license.\n\n"
	            "%2 for details.");

	return QString(str).arg(copyright()).arg(see);
}


QString About::license() {

	static const char* str = "%1\n\n"
	"License\n"
	"=========\n"
	"This software may be distributed, used, and modified under the terms of\n"
	"BSD license:\n"
	"\n"
	"Redistribution and use in source and binary forms, with or without\n"
	"modification, are permitted provided that the following conditions are\n"
	"met:\n"
	"\n"
	"1. Redistributions of source code must retain the above copyright\n"
	"   notice, this list of conditions and the following disclaimer.\n"
	"\n"
	"2. Redistributions in binary form must reproduce the above copyright\n"
	"   notice, this list of conditions and the following disclaimer in the\n"
	"   documentation and/or other materials provided with the distribution.\n"
	"\n"
	"3. Neither the name(s) of the above-listed copyright holder(s) nor the\n"
	"   names of its contributors may be used to endorse or promote products\n"
	"   derived from this software without specific prior written permission.\n"
	"\n"
	"THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
	"\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
	"LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
	"A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n"
	"OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
	"SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
	"LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
	"DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
	"THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
	"(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
	"OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.";

	return QString(str).arg(copyright());
}

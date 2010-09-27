/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*-
 *
 * Copyright (C) 2007-2009 Tadas Dailyda <tadas@dailyda.com>
 *
 * Licensed under the GNU General Public License Version 2
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __ODS_COMMON_H_
#define __ODS_COMMON_H_

#include <dbus/dbus-glib.h>
#include <time.h>

/* Reference to the type of BUS we are using */
extern DBusBusType ODS_DBUS_BUS;
#define	ODS_DBUS_SERVICE		"org.openobex"
/* ods API version (every incompatible version increases this number) */
#define ODS_API_VERSION			1

#define EOL_CHARS "\n"

enum {
	ODS_SERVICE_GOEP = 1,
	ODS_SERVICE_OPP,
	ODS_SERVICE_FTP,
	ODS_SERVICE_PBAP,
	ODS_SERVICE_BIP
};

/** Standard folder browsing service UUID */
#define OBEX_FTP_UUID \
    "\xF9\xEC\x7B\xC4\x95\x3C\x11\xD2\x98\x4E\x52\x54\x00\xDC\x9E\x09"

/** Nokia OBEX PC Suite Services (used instead of standard FTP for some devices) */
#define OBEX_NOKIAFTP_UUID \
	"\x00\x00\x50\x05\x00\x00\x10\x00\x80\x00\x00\x02\xEE\x00\x00\x01"

/** Phone Book Access Profile UUID */
#define OBEX_PBAP_UUID \
    "\x79\x61\x35\xF0\xF0\xC5\x11\xD8\x09\x66\x08\x00\x20\x0C\x9A\x66"

/** Basic Imaging Image Push */
#define OBEX_BIP_IPUSH_UUID \
	"\xE3\x3D\x95\x45\x83\x74\x4A\xD7\x9E\xC5\xC1\x6B\xE3\x1E\xDE\x8E"

/** Basic Imaging Image Pull */
#define OBEX_BIP_IPULL_UUID \
	"\x8E\xE9\xB3\xD0\x46\x08\x11\xD5\x84\x1A\x00\x02\xA5\x32\x5B\x4E"

/** Basic Imaging Advanced Image Printing */
#define OBEX_BIP_AIP_UUID \
	"\x92\x35\x33\x50\x46\x08\x11\xD5\x84\x1A\x00\x02\xA5\x32\x5B\x4E"

/** Basic Imaging Automatic Archive */
#define OBEX_BIP_AA_UUID \
	"\x94\x01\x26\xC0\x46\x08\x11\xD5\x84\x1A\x00\x02\xA5\x32\x5B\x4E"

/** Basic Imaging Remote Camera */
#define OBEX_BIP_RC_UUID \
	"\x94\x7E\x74\x20\x46\x08\x11\xD5\x84\x1A\x00\x02\xA5\x32\x5B\x4E"

/** Basic Imaging Remote Display */
#define OBEX_BIP_RD_UUID \
	"\x94\xC7\xCD\x20\x46\x08\x11\xD5\x84\x1A\x00\x02\xA5\x32\x5B\x4E"

/** Basic Imaging Referenced Objects */
#define OBEX_BIP_RO_UUID \
	"\x8E\x61\xF9\x5D\x1A\x79\x11\xD4\x8E\xA4\x00\x80\x5F\x9B\x98\x34"

/** Basic Imaging Archived Objects */
#define OBEX_BIP_AO_UUID \
	"\x8E\x61\xF9\x5E\x1A\x79\x11\xD4\x8E\xA4\x00\x80\x5F\x9B\x98\x34"

/** Length of UUIDs */
#define OBEX_UUID_LEN 16

#define ODS_OPP_RFCOMM_CHANNEL	9
#define ODS_FTP_RFCOMM_CHANNEL	10
#define ODS_BIP_RFCOMM_CHANNEL	11
#define ODS_PBAP_RFCOMM_CHANNEL 15

#define ODS_SYNC_L2CAP_PSM 	0x1003
#define ODS_BIP_L2CAP_PSM 	0x1005 
#define ODS_PBAP_L2CAP_PSM 	0x1013
#define ODS_OPP_L2CAP_PSM	0x1015
#define ODS_FTP_L2CAP_PSM	0x1001
#define SDP_ATTR_GOEP2_PSM	0x0200	

#define L2CAP_OBEX			1
#define RFCOMM_OBEX			0

gboolean	ods_check_bluetooth_address (const gchar *str);
gboolean	ods_check_caller (DBusGMethodInvocation *context, const gchar *owner);
gsize		ods_filename_to_utf16 (gchar **filename_utf16, const gchar *filename);
gchar		*ods_filename_from_utf16 (const gchar *filename_utf16, gssize len);
gint		ods_make_iso8601 (time_t time, gchar *str, gint len);
time_t		ods_parse_iso8601 (const gchar *str, gint len);

GList		*ods_hash_table_get_keys(GHashTable *table);
gchar		**ods_hash_table_keys2strv (GHashTable *list);
gboolean	ods_safe_gsource_remove (guint *tag);

#endif /*__ODS_COMMON_H_*/

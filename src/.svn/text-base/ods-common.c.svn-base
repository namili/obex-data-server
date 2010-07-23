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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <glib.h>

#include "ods-common.h"
#include "ods-error.h"

/* There shouldn't been a need to init this global variable, but let's do it
 * just in case */
DBusBusType ODS_DBUS_BUS=DBUS_BUS_SESSION;

gboolean
ods_check_caller (DBusGMethodInvocation *context, const gchar *owner)
{
	gchar 		*caller;
	GError		*error = NULL;
	gboolean	ret = FALSE;

	/* check if caller matches owner of some object */
	caller = dbus_g_method_get_sender (context);
	if (strcmp (caller, owner)) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_NOT_AUTHORIZED,
		             "Not authorized");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		goto out;
	}
	ret = TRUE;
out:
	g_free (caller);
	return ret;
}

gsize
ods_filename_to_utf16 (gchar **filename_utf16, const gchar *filename)
{
	gsize	utf16_len;
	gchar	*filename_utf8;
	GError	*error = NULL;

	if (*filename == '\0') {
		*filename_utf16 = "";
		return 0;
	}

	/* convert local filename to utf8 */
	filename_utf8 = g_filename_to_utf8 (filename, -1, NULL, NULL, &error);
	if (filename_utf8 == NULL) {
		g_message ("ods_filename_to_utf16 error: %s", error->message);
		g_error_free (error);
		*filename_utf16 = NULL;
		return 0;
	}

	/* convert utf8 to utf16 (big endian) */
	*filename_utf16 = g_convert (filename_utf8, -1, "UTF16BE", "UTF8", NULL, &utf16_len, &error);

	if (*filename_utf16 == NULL) {
		g_message ("ods_filename_to_utf16 error: %s", error->message);
		g_error_free (error);
		utf16_len = 0;
	}

	g_free (filename_utf8);
	(*filename_utf16)[utf16_len+1] = '\0';/* set trailing 0 */
	return utf16_len+2;/* utf16_len does not include trailing 0 */
}

gchar *
ods_filename_from_utf16 (const gchar *filename_utf16, gssize len)
{
	GError	*error = NULL;
	gchar	*filename_utf8;
	gchar	*filename;

	/* convert utf16 (big endian) to utf8 */
	filename_utf8 = g_convert (filename_utf16, len, "UTF8", "UTF16BE", NULL, NULL, &error);
	if (filename_utf8 == NULL) {
		g_message ("ods_filename_from_utf16 error: %s", error->message);
		g_error_free (error);
		return NULL;
	}

	/* convert to local filename */
	filename = g_filename_from_utf8 (filename_utf8, -1, NULL, NULL, &error);
	if (filename == NULL) {
		g_message ("ods_filename_from_utf16 error: %s", error->message);
		g_error_free (error);
	}

	g_free (filename_utf8);
	return filename;
}

gint
ods_make_iso8601 (time_t time, gchar *str, gint len)
{
	struct tm tm;
#if defined(HAVE_TIMEZONE) && defined(USE_LOCALTIME)
	time_t tz_offset = 0;

	tz_offset = -timezone;
	if (daylight > 0)
		tz_offset += 3600;
	time += tz_offset;
#endif

	if (gmtime_r(&time, &tm) == NULL)
		return -1;

	tm.tm_year += 1900;
	tm.tm_mon++;

	return snprintf(str, len,
#ifdef USE_LOCALTIME
	                "%04u%02u%02uT%02u%02u%02u",
#else
	                "%04u%02u%02uT%02u%02u%02uZ",
#endif
	                tm.tm_year, tm.tm_mon, tm.tm_mday,
	                tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* From Imendio's GnomeVFS OBEX module (om-utils.c) */
time_t
ods_parse_iso8601 (const gchar *str, gint len)
{
	gchar    *tstr;
	struct tm tm;
	gint      nr;
	gchar     tz;
	time_t    time;
	time_t    tz_offset = 0;

	memset (&tm, 0, sizeof (struct tm));

	/* According to spec the time doesn't have to be null terminated */
	if (str[len - 1] != '\0') {
		tstr = g_malloc(len + 1);
		strncpy(tstr, str, len);
		tstr[len] = '\0';
	} else {
		tstr = g_strdup(str);
	}

	nr = sscanf (tstr, "%04u%02u%02uT%02u%02u%02u%c",
	             &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
	             &tm.tm_hour, &tm.tm_min, &tm.tm_sec,
	             &tz);

	g_free(tstr);

	/* Fixup the tm values */
	tm.tm_year -= 1900;       /* Year since 1900 */
	tm.tm_mon--;              /* Months since January, values 0-11 */
	tm.tm_isdst = -1;         /* Daylight savings information not avail */

	if (nr < 6) {
		/* Invalid time format */
		return -1;
	}

	time = mktime (&tm);

#if defined(HAVE_TM_GMTOFF)
	tz_offset = tm.tm_gmtoff;
#elif defined(HAVE_TIMEZONE)
	tz_offset = -timezone;
	if (tm.tm_isdst > 0) {
		tz_offset += 3600;
	}
#endif

	if (nr == 7) { /* Date/Time was in localtime (to remote device)
					* already. Since we don't know anything about the
					* timezone on that one we won't try to apply UTC offset
					*/
		time += tz_offset;
	}

	return time;
}

static void
prepend_key_to_list(gpointer key, gpointer value, GList **list_keys)
{
	*list_keys = g_list_prepend (*list_keys, key);
}

/* Implemented for better portability */
GList *
ods_hash_table_get_keys(GHashTable *table)
{
	GList *list_keys = NULL;

	g_hash_table_foreach (table, (GHFunc) prepend_key_to_list, &list_keys);

	return list_keys;
}

gchar**
ods_hash_table_keys2strv (GHashTable *list)
{
	guint list_size, i = 0;
	GHashTableIter iter;
	gpointer key, value;
	gchar **list_keys = NULL;

	list_size = g_hash_table_size (list);
	if (list_size) {
		list_keys = malloc (sizeof(gchar*) * (list_size+1));
		g_hash_table_iter_init (&iter, list);
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			list_keys[i] = g_strdup (key);
			i++;
		}
		list_keys[i] = NULL;
	}

	return list_keys;
}

/* safely removes event source
 * (checks if source exists before calling g_source_remove
 * and resets tag value) */
gboolean
ods_safe_gsource_remove (guint *tag)
{
	GSource* source;
	gboolean ret = FALSE;

	if (!*tag)
		return FALSE;
	source = g_main_context_find_source_by_id (g_main_context_default(), *tag);
	if (source) {
		ret = g_source_remove (*tag);
		*tag = 0;
	}

	return ret;
}

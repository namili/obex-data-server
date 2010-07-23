/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*-
 *
 * Copyright (C) 2008 Tadas Dailyda <tadas@dailyda.com>
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

#include <glib.h>
#include <string.h>
#include <sys/statvfs.h>

#define ODS_INS_BEGIN		"{$"
#define ODS_INS_BEGIN_LEN	2
#define ODS_INS_ARG			'|'
#define ODS_INS_END			'}'
#define ODS_INS_ODS_VER		"ODS_VER"
#define ODS_INS_MEM_FREE	"MEM_FREE"
#define ODS_INS_MEM_USED	"MEM_USED"

#define ODS_CAP				"obex-data-server/capability.xml"
#define ODS_IMAGING_CAP		"obex-data-server/imaging_capabilities.xml"

static gchar*
ods_get_variable (const gchar *var, gssize var_len,
                  const gchar *var_arg, gssize var_arg_len,
                  const gchar *set_path)
{
	gchar			*arg = NULL;
	gchar			*ret = NULL;
	struct statvfs	sfs;
	gchar			*new_path = NULL;

	if (var_arg_len > 0)
		arg = g_strndup (var_arg, var_arg_len);

	if (!strncmp (var, ODS_INS_ODS_VER, var_len)) {
		/* ODS_INS_ODS_VER  {$ODS_VER} */
		ret = g_strdup (VERSION);
	} else if (!strncmp (var, ODS_INS_MEM_FREE, var_len)) {
		/* ODS_INS_MEM_FREE  {$MEM_FREE|<set_path>} */
		if (arg)
			new_path = g_build_filename (set_path, arg, NULL);
		if (statvfs (arg ? new_path : set_path, &sfs) == -1)
			ret = g_strdup ("0");
		else
			ret = g_strdup_printf ("%" G_GUINT64_FORMAT,
			                       (guint64)sfs.f_frsize * sfs.f_bfree);
	} else if (!strncmp (var, ODS_INS_MEM_USED, var_len)) {
		/* ODS_INS_MEM_USED  {$MEM_USED|<set_path>} */
		if (arg)
			new_path = g_build_filename (set_path, arg, NULL);
		if (statvfs (arg ? new_path : set_path, &sfs) == -1)
			ret = g_strdup ("0");
		else
			ret = g_strdup_printf ("%" G_GUINT64_FORMAT,
			                       (guint64)sfs.f_frsize * (sfs.f_blocks-sfs.f_bfree));
	} else {
		/* unknown variable name */
		ret = g_strdup ("");
	}

	if (arg)
		g_free (arg);
	if (new_path)
		g_free (new_path);
	return ret;
}

static gchar*
ods_insert_variables (const gchar *template, const gchar *set_path)
{
	GString		*output;
	const gchar	*templ, *templ_pos;
	gchar		*var = NULL;
	gssize		var_len = -1;
	gssize		var_arg_len = -1;
	gint		i;

	g_assert (*template != '\0');

	output = g_string_new ("");
	templ = template;
	/* search for variable to insert */
	while ((templ_pos = strstr (templ, ODS_INS_BEGIN))) {
		/* append everything before var to output */
		output = g_string_append_len (output, templ, templ_pos-templ);
		templ_pos += ODS_INS_BEGIN_LEN;

		for (i=1;;i++) {
			if (*(templ_pos+i) == '\0')
				break;
			if (*(templ_pos+i) == ODS_INS_ARG) {
				var_len = i;
			} else if (*(templ_pos+i) == ODS_INS_END) {
				if (var_len == -1)
					var_len = i;
				else
					var_arg_len = i-var_len-1;
				break;
			}
		}
		if (var_len == -1) {
			/* invalid var definition, strip it from output */
			templ = templ_pos;
			break;
		}
		/* we got variable and argument now */
		var = ods_get_variable (templ_pos, var_len,
		                        templ_pos+var_len+1, var_arg_len,
		                        set_path);
		output = g_string_append (output, var);
		g_free (var);
		/* change next search position */
		templ = templ_pos+i+1;
		var_len = -1;
		var_arg_len = -1;
	}
	/* append what is left */
	output = g_string_append (output, templ);

	return g_string_free (output, FALSE);
}

gchar*
ods_get_capability (const gchar *root_path)
{
	gchar			*conf_file;
	gchar			*contents = NULL;
	GError			*error = NULL;
	gchar			*capability = NULL;

	conf_file = g_build_filename (CONFIGDIR, ODS_CAP, NULL);
	if (!g_file_get_contents (conf_file, &contents, NULL, &error)) {
		g_warning ("Could not read configuration file %s (%s)",
		           conf_file, error->message);
		g_clear_error (&error);
	} else {
		capability = ods_insert_variables (contents, root_path);
	}

	g_free (conf_file);
	if (contents)
		g_free (contents);
	return capability;
}

gchar*
ods_get_imaging_capabilities ()
{
	gchar			*conf_file;
	gchar			*contents = NULL;
	GError			*error = NULL;

	conf_file = g_build_filename (CONFIGDIR, ODS_IMAGING_CAP, NULL);
	if (!g_file_get_contents (conf_file, &contents, NULL, &error)) {
		g_warning ("Could not read configuration file %s (%s)",
		           conf_file, error->message);
		g_clear_error (&error);
	}

	g_free (conf_file);
	return contents;
}

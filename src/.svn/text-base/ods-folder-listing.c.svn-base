/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*-
 *
 * Copyright (C) 2007-2008 Tadas Dailyda <tadas@dailyda.com>
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

#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <glib.h>

#include "ods-common.h"


#define FL_XML_VERSION "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" EOL_CHARS

#define FL_XML_TYPE "<!DOCTYPE folder-listing SYSTEM \"obex-folder-listing.dtd\">" EOL_CHARS

#define FL_XML_BODY_BEGIN "<folder-listing version=\"1.0\">" EOL_CHARS

#define FL_XML_BODY_END "</folder-listing>" EOL_CHARS

#define FL_XML_PARENT_FOLDER_ELEMENT "<parent-folder/>" EOL_CHARS

#define FL_XML_FILE_ELEMENT "<file name=\"%s\" size=\"%" G_GUINT64_FORMAT "\"" \
							" %s accessed=\"%s\" " \
							"modified=\"%s\" created=\"%s\"/>" EOL_CHARS

#define FL_XML_FOLDER_ELEMENT "<folder name=\"%s\" %s accessed=\"%s\" " \
							  "modified=\"%s\" created=\"%s\"/>" EOL_CHARS

inline static gchar *
get_permission_string (mode_t file, mode_t folder, gboolean allow_write)
{
	return g_strdup_printf (
	           "user-perm=\"%s%s%s\" group-perm=\"%s%s%s\" other-perm=\"%s%s%s\"",
	           (file & S_IRUSR ? "R" : ""),
	           (file & S_IWUSR && allow_write ? "W" : ""),
	           (folder & S_IWUSR ? "D" : ""),
	           (file & S_IRGRP ? "R" : ""),
	           (file & S_IWGRP && allow_write ? "W" : ""),
	           (folder & S_IWGRP ? "D" : ""),
	           (file & S_IROTH ? "R" : ""),
	           (file & S_IWOTH && allow_write ? "W" : ""),
	           (folder & S_IWOTH ? "D" : ""));
}

gchar*
get_folder_listing (const gchar *path, const gchar *root_path, gboolean allow_write)
{
	GString			*listing;
	struct dirent	*dirp;
	DIR				*dp;
	struct stat		dirstat;
	struct stat		filestat;
	gchar			*filename = NULL;
	gchar			*filename_utf8;
	GError			*error = NULL;
	gboolean		is_dir;
	gchar			*perm_str = NULL;
	gchar			atime_str[17];
	gchar			mtime_str[17];
	gchar			ctime_str[17];

	listing = g_string_new ("");
	listing = g_string_append (listing, FL_XML_VERSION);
	listing = g_string_append (listing, FL_XML_TYPE);
	listing = g_string_append (listing, FL_XML_BODY_BEGIN);
	/* Add parent folder element if path!=root_path */
	if (strcmp (path, root_path))
		listing = g_string_append (listing, FL_XML_PARENT_FOLDER_ELEMENT);

	/* Go through directory, add file and folder elements */
	stat (path, &dirstat);
	dp = opendir (path);
	while (dp != NULL && (dirp = readdir (dp))) {
		if (dirp->d_name[0] == '.')
			continue;

		filename = g_build_filename (path, dirp->d_name, NULL);
		filename_utf8 = g_filename_to_utf8 (dirp->d_name, -1, NULL, NULL, &error);
		if (filename_utf8 == NULL) {
			g_message ("get_folder_listing error: %s", error->message);
			g_clear_error (&error);
			/* continue anyway */
			g_free (filename);
			continue;
		}

		/* stat file */
		lstat (filename, &filestat);
		is_dir = S_ISDIR (filestat.st_mode);

		/* get permission string */
		perm_str = get_permission_string (filestat.st_mode, dirstat.st_mode,
		                                  allow_write);
		/* get time strings */
		ods_make_iso8601 (filestat.st_atime, atime_str, sizeof (atime_str));
		ods_make_iso8601 (filestat.st_mtime, mtime_str, sizeof (mtime_str));
		ods_make_iso8601 (filestat.st_ctime, ctime_str, sizeof (ctime_str));

		if (is_dir) {
			g_string_append_printf (listing, FL_XML_FOLDER_ELEMENT,
			                        filename_utf8, perm_str, atime_str,
			                        mtime_str, ctime_str);
		} else {
			g_string_append_printf (listing, FL_XML_FILE_ELEMENT,
			                        filename_utf8, (guint64) filestat.st_size,
			                        perm_str, atime_str, mtime_str, ctime_str);
		}

		/* free mem */
		g_free (filename);
		g_free (filename_utf8);
		g_free (perm_str);
	}
	closedir (dp);
	listing = g_string_append (listing, FL_XML_BODY_END);

	return g_string_free (listing, FALSE);
}

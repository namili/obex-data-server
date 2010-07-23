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

#ifndef __ODS_IMAGING_HELPERS_H_
#define __ODS_IMAGING_HELPERS_H_

#include <glib.h>

enum {
	ODS_IMAGING_TRANSFORMATION_STRETCH = 1,
	ODS_IMAGING_TRANSFORMATION_CROP,
	ODS_IMAGING_TRANSFORMATION_FILL
};

#define ODS_IMAGING_TRANSFORMATION_STRETCH_STR	"stretch"
#define ODS_IMAGING_TRANSFORMATION_CROP_STR		"crop"
#define ODS_IMAGING_TRANSFORMATION_FILL_STR		"fill"

#define ODS_IMAGING_THUMBNAIL_WIDTH		160
#define ODS_IMAGING_THUMBNAIL_HEIGHT	120
#define ODS_IMAGING_THUMBNAIL_ENCODING	"JPEG"

typedef struct OdsImageInfo_ {
	gchar	*filename;
	gchar	*resized_image_filename;
	gulong	width;
	gulong	height;
	gchar	*encoding;
	guint	transformation;
	goffset	size;
} OdsImageInfo;

typedef void (* OdsImagingFunc)	(OdsImageInfo*, gpointer);

gchar*	get_image_descriptor (const gchar *encoding, const gchar *pixel,
						guint64 size, const gchar *transformation);
gchar*	get_attachment_descriptor (const gchar *name, guint64 size,
						const gchar *content_type, const gchar *charset,
						const gchar *created);
void	parse_image_descriptor (const gchar *descriptor, gchar **encoding,
						gchar **pixel, guint64 *size,
						gchar **transformation);
void	parse_attachment_descriptor (const gchar *descriptor, gchar **name,
						guint64 *size, gchar **content_type,
						gchar **charset, gchar **created);
void		ods_image_info_free (OdsImageInfo *info);
gchar*		ods_imaging_get_pixel_string (gulong width, gulong height);
const gchar* ods_imaging_get_transformation_string (guint transformation);
guint		ods_imaging_get_transformation (const gchar *trans);
gboolean	ods_imaging_get_image_info_async (const gchar *filename,
						OdsImagingFunc func, gpointer data);
gboolean	ods_imaging_resize_image_async (const gchar *filename, gulong width,
						gulong height, const gchar *encoding, guint transformation,
						OdsImagingFunc func, gpointer data);
gboolean	ods_imaging_make_image_thumbnail_async (const gchar *filename,
						OdsImagingFunc func, gpointer data);


#endif /*__ODS_IMAGING_HELPERS_H_*/

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
#include <glib/gstdio.h>
#include <unistd.h>
#ifdef USE_IMAGEMAGICK
#include <wand/MagickWand.h>
#endif
#ifdef USE_GDKPIXBUF
#include <gdk-pixbuf/gdk-pixbuf.h>
#endif

#include "ods-common.h"
#include "ods-imaging-helpers.h"


#define ODS_IMAGING_FILL_COLOR "#FFFFFF"
#define ODS_IMAGING_FILL_COLOR_RGBA 0xFFFFFFFF

#define ODS_IMAGING_TEMPNAME "ods_imageXXXXXX"

/* constants for generating XML */

#define IMG_DESCRIPTOR "<image-descriptor version=\"1.0\">" EOL_CHARS

#define IMG_DESCRIPTOR_IMG_SIZE "size=\"%" G_GUINT64_FORMAT "\" "

#define IMG_DESCRIPTOR_IMG_TRANSFORMATION "transformation=\"%s\" "

#define IMG_DESCRIPTOR_IMG "<image encoding=\"%s\" pixel=\"%s\" %s/>" EOL_CHARS

#define IMG_DESCRIPTOR_END "</image-descriptor>" EOL_CHARS

#define ATT_DESCRIPTOR "<attachment-descriptor version=\"1.0\">" EOL_CHARS

#define ATT_DESCRIPTOR_ATT_CONTENT_TYPE "content-type=\"%s\" "

#define ATT_DESCRIPTOR_ATT_CHARSET "charset=\"%s\" "

#define ATT_DESCRIPTOR_ATT_CREATED "created=\"%s\" "

#define ATT_DESCRIPTOR_ATT "<attachment name=\"%s\"" \
						   " size=\"%" G_GUINT64_FORMAT "\" %s/>" EOL_CHARS

#define ATT_DESCRIPTOR_END "</attachment-descriptor>" EOL_CHARS

typedef struct OdsImagingCallbackData_ {
	OdsImagingFunc	func;
	OdsImageInfo	*data;
	gpointer		user_data;
} OdsImagingCallbackData;

/* constants for parsing XML */

#define IMG_ELEMENT "image"
#define ATT_ELEMENT "attachment"

typedef struct OdsImgDescriptorParse_ {
	/* Used for Image and Attachment descriptors */
	gchar	**encoding;
	gchar	**pixel;
	guint64	*size;
	gchar	**transformation;
	/* attachment specific */
	gchar	**name;
	gchar	**content_type;
	gchar	**charset;
	gchar	**created;
} OdsImgDescriptorParse;

/* encoding, pixel and transformation can be empty but must not be NULL */
gchar*
get_image_descriptor (const gchar *encoding, const gchar *pixel, guint64 size,
                      const gchar *transformation)
{
	GString		*descriptor;
	GString		*descriptor_optional;
	gchar		*descriptor_optional_chr;

	g_assert (encoding && pixel && transformation);

	descriptor = g_string_new ("");
	descriptor_optional = g_string_new ("");

	descriptor = g_string_append (descriptor, IMG_DESCRIPTOR);
	if (size > 0)
		g_string_append_printf (descriptor_optional,
		                        IMG_DESCRIPTOR_IMG_SIZE, size);
	if (*transformation != '\0')
		g_string_append_printf (descriptor_optional,
		                        IMG_DESCRIPTOR_IMG_TRANSFORMATION, transformation);
	descriptor_optional_chr = g_string_free (descriptor_optional, FALSE);
	g_string_append_printf (descriptor, IMG_DESCRIPTOR_IMG, encoding,
	                        pixel, descriptor_optional_chr);
	descriptor = g_string_append (descriptor, IMG_DESCRIPTOR_END);

	g_free (descriptor_optional_chr);
	return g_string_free (descriptor, FALSE);
}

/* content_type, charset and created can be empty but must not be NULL */
gchar*
get_attachment_descriptor (const gchar *name, guint64 size, const gchar *content_type,
                           const gchar *charset, const gchar *created)
{
	GString		*descriptor;
	GString		*descriptor_optional;
	gchar		*descriptor_optional_chr;

	g_assert (name && content_type && charset && created);

	descriptor = g_string_new ("");
	descriptor_optional = g_string_new ("");

	descriptor = g_string_append (descriptor, ATT_DESCRIPTOR);
	if (*content_type != '\0')
		g_string_append_printf (descriptor_optional,
		                        ATT_DESCRIPTOR_ATT_CONTENT_TYPE, content_type);
	if (*charset != '\0')
		g_string_append_printf (descriptor_optional,
		                        ATT_DESCRIPTOR_ATT_CHARSET, charset);
	if (*created != '\0')
		g_string_append_printf (descriptor_optional,
		                        ATT_DESCRIPTOR_ATT_CREATED, created);
	descriptor_optional_chr = g_string_free (descriptor_optional, FALSE);
	g_string_append_printf (descriptor, ATT_DESCRIPTOR_ATT, name,
	                        size, descriptor_optional_chr);
	descriptor = g_string_append (descriptor, ATT_DESCRIPTOR_END);

	g_free (descriptor_optional_chr);
	return g_string_free (descriptor, FALSE);
}

static void
img_parse_element_start (GMarkupParseContext *context,
                         const gchar *element_name,
                         const gchar **attribute_names,
                         const gchar **attribute_values,
                         gpointer data,
                         GError **error)
{
	OdsImgDescriptorParse	*out_vars;
	gboolean				ret;
	const gchar				*size_str = NULL;

	out_vars = (OdsImgDescriptorParse*)data;

	if (g_ascii_strncasecmp (element_name, IMG_ELEMENT, strlen (element_name)) &&
	        g_ascii_strncasecmp (element_name, ATT_ELEMENT, strlen (element_name))) {
		/* we are only parsing <image> and <attachment> elements */
		return;
	}
	ret = g_markup_collect_attributes (element_name, attribute_names,
	                                   attribute_values, error,
	                                   /* encoding */
	                                   G_MARKUP_COLLECT_STRDUP | G_MARKUP_COLLECT_OPTIONAL,
	                                   "encoding",
	                                   out_vars->encoding,
	                                   /* pixel */
	                                   G_MARKUP_COLLECT_STRDUP | G_MARKUP_COLLECT_OPTIONAL,
	                                   "pixel",
	                                   out_vars->pixel,
	                                   /* size */
	                                   G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL,
	                                   "size",
	                                   &size_str,
	                                   /* maxsize (ignore) */
	                                   G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL,
	                                   "maxsize",
	                                   NULL,
	                                   /* transformation */
	                                   G_MARKUP_COLLECT_STRDUP | G_MARKUP_COLLECT_OPTIONAL,
	                                   "transformation",
	                                   out_vars->transformation,
	                                   /* name */
	                                   G_MARKUP_COLLECT_STRDUP | G_MARKUP_COLLECT_OPTIONAL,
	                                   "name",
	                                   out_vars->name,
	                                   /* content_type */
	                                   G_MARKUP_COLLECT_STRDUP | G_MARKUP_COLLECT_OPTIONAL,
	                                   "content-type",
	                                   out_vars->content_type,
	                                   /* charset */
	                                   G_MARKUP_COLLECT_STRDUP | G_MARKUP_COLLECT_OPTIONAL,
	                                   "charset",
	                                   out_vars->charset,
	                                   /* created */
	                                   G_MARKUP_COLLECT_STRDUP | G_MARKUP_COLLECT_OPTIONAL,
	                                   "created",
	                                   out_vars->created,
	                                   G_MARKUP_COLLECT_INVALID);
	if (!ret)
		g_message ("Parsing descriptor XML data element failed");
	if (size_str)
		*(out_vars->size) = g_ascii_strtoull (size_str, NULL, 10);
}

static void
parse_descriptor (const gchar *descriptor, OdsImgDescriptorParse *out_vars)
{
	GMarkupParser			*parser;
	GMarkupParseContext		*parse_ctx;
	gboolean				ret;
	GError					*error = NULL;

	g_assert (descriptor);

	parser = g_new0 (GMarkupParser, 1);
	parser->start_element = img_parse_element_start;

	parse_ctx = g_markup_parse_context_new (parser, 0, out_vars, NULL);
	ret = g_markup_parse_context_parse (parse_ctx, descriptor,
	                                    strlen (descriptor), &error);
	/* parsing error is not fatal,
	 * we can continue without data provided in descriptor */
	if (!ret) {
		g_message ("Failed to parse descriptor XML data (%s)", error->message);
		g_clear_error (&error);
	} else {
		ret = g_markup_parse_context_end_parse (parse_ctx, &error);
		if (!ret) {
			g_message ("Failed to parse descriptor XML data (%s)", error->message);
			g_clear_error (&error);
		}
	}

	g_markup_parse_context_free (parse_ctx);
	g_free (parser);
}

void
parse_image_descriptor (const gchar *descriptor, gchar **encoding,
                        gchar **pixel, guint64 *size,
                        gchar **transformation)
{
	OdsImgDescriptorParse	*out_vars;

	g_assert (encoding && pixel && size && transformation);
	out_vars = g_new0 (OdsImgDescriptorParse, 1);
	out_vars->encoding = encoding;
	out_vars->pixel = pixel;
	out_vars->size = size;
	out_vars->transformation = transformation;

	parse_descriptor (descriptor, out_vars);

	g_free (out_vars);
}

void
parse_attachment_descriptor (const gchar *descriptor, gchar **name,
                             guint64 *size, gchar **content_type,
                             gchar **charset, gchar **created)
{
	OdsImgDescriptorParse	*out_vars;

	g_assert (name && size && content_type && charset && created);
	out_vars = g_new0 (OdsImgDescriptorParse, 1);
	out_vars->name = name;
	out_vars->size = size;
	out_vars->content_type = content_type;
	out_vars->charset = charset;
	out_vars->created = created;
	parse_descriptor (descriptor, out_vars);

	g_free (out_vars);
}

void
ods_image_info_free (OdsImageInfo *info)
{
	if (info->filename)
		g_free (info->filename);
	if (info->resized_image_filename)
		g_free (info->resized_image_filename);
	if (info->encoding)
		g_free (info->encoding);
	g_free (info);
}

gchar*
ods_imaging_get_pixel_string (gulong width, gulong height)
{
	return g_strdup_printf ("%lu*%lu", width, height);
}

const gchar*
ods_imaging_get_transformation_string (guint transformation)
{
	switch (transformation) {
		case ODS_IMAGING_TRANSFORMATION_STRETCH:
			return ODS_IMAGING_TRANSFORMATION_STRETCH_STR;
		case ODS_IMAGING_TRANSFORMATION_CROP:
			return ODS_IMAGING_TRANSFORMATION_CROP_STR;
		case ODS_IMAGING_TRANSFORMATION_FILL:
			return ODS_IMAGING_TRANSFORMATION_FILL_STR;
		default:
			return "";
	}
}

guint
ods_imaging_get_transformation (const gchar *trans)
{
	if (!g_ascii_strcasecmp (trans, ODS_IMAGING_TRANSFORMATION_STRETCH_STR))
		return ODS_IMAGING_TRANSFORMATION_STRETCH;
	if (!g_ascii_strcasecmp (trans, ODS_IMAGING_TRANSFORMATION_CROP_STR))
		return ODS_IMAGING_TRANSFORMATION_CROP;
	if (!g_ascii_strcasecmp (trans, ODS_IMAGING_TRANSFORMATION_FILL_STR))
		return ODS_IMAGING_TRANSFORMATION_FILL;
	return 0;
}

#if defined(USE_IMAGEMAGICK) || defined (USE_GDKPIXBUF)

static gboolean
ods_imaging_thread_callback (OdsImagingCallbackData *cb_data)
{
	cb_data->func (cb_data->data, cb_data->user_data);
	return FALSE;
}

#endif /* USE_IMAGEMAGICK || USE_GDKPIXBUF */

#ifdef USE_IMAGEMAGICK
static void
ods_imaging_get_image_info (OdsImagingCallbackData *cb_data)
{
	MagickBooleanType	wand_ret;
	MagickWand			*magick_wand;
	OdsImageInfo		*image_info;
	struct stat			file_stat;


	image_info = cb_data->data;
	MagickWandGenesis ();
	magick_wand = NewMagickWand ();
	/* read the image */
	wand_ret = MagickReadImage (magick_wand, image_info->filename);
	if (wand_ret == MagickFalse)
		goto out;

	/* get info */
	image_info->width = MagickGetImageWidth (magick_wand);
	image_info->height = MagickGetImageHeight (magick_wand);
	image_info->encoding = MagickGetImageFormat (magick_wand);
	if (g_stat (image_info->filename, &file_stat) == 0)
		image_info->size = file_stat.st_size;

out:
	magick_wand = DestroyMagickWand (magick_wand);
	MagickWandTerminus ();

	g_idle_add ((GSourceFunc)ods_imaging_thread_callback, cb_data);
}

static void
ods_imaging_resize_image (OdsImagingCallbackData *cb_data)
{
	OdsImageInfo		*info;
	MagickBooleanType	ret;
	MagickWand			*magick_wand;
	gchar				*current_encoding = NULL;
	gulong				current_width = 0;
	gulong				current_height = 0;
	gboolean			do_resize;
	gboolean			do_encode;
	struct stat			file_stat;


	g_message("resize_image thread started");
	info = cb_data->data;
	MagickWandGenesis ();
	magick_wand = NewMagickWand ();
	/* read the image */
	ret = MagickReadImage (magick_wand, info->filename);
	if (ret == MagickFalse)
		goto out;

	/* get image info and determine what we need to do */
	current_encoding = MagickGetImageFormat (magick_wand);
	current_width = MagickGetImageWidth (magick_wand);
	current_height = MagickGetImageHeight (magick_wand);
	do_encode = info->encoding && strcmp (info->encoding, current_encoding);
	do_resize = (info->width != current_width) ||
	            (info->height != current_height);

	/* resize image if needed */
	if (do_resize) {
		if (info->transformation == ODS_IMAGING_TRANSFORMATION_CROP) {
			/* Transformation CROP */
			if (info->width > current_width || info->height > current_height)
				info->transformation = ODS_IMAGING_TRANSFORMATION_STRETCH;
			else {
				ret = MagickCropImage (magick_wand, info->width,
				                       info->height, 0, 0);
				if (ret == MagickFalse)
					goto out;
			}
		} else if (info->transformation == ODS_IMAGING_TRANSFORMATION_FILL) {
			/* Transformation FILL */
			if (info->width < current_width || info->height < current_height)
				info->transformation = ODS_IMAGING_TRANSFORMATION_STRETCH;
			else {
				MagickWand	*composite_wand;
				PixelWand	*pixel_wand;

				composite_wand = magick_wand;
				magick_wand = NewMagickWand ();
				pixel_wand = NewPixelWand ();
				PixelSetColor (pixel_wand, ODS_IMAGING_FILL_COLOR);
				ret = MagickNewImage (magick_wand, info->width,
				                      info->height, pixel_wand);
				if (!info->encoding)
					info->encoding = current_encoding;
				do_encode = TRUE;
				DestroyPixelWand (pixel_wand);
				if (ret == MagickFalse) {
					DestroyMagickWand (composite_wand);
					goto out;
				}

				ret = MagickCompositeImage (magick_wand, composite_wand,
				                            SrcOverCompositeOp, 0, 0);
				DestroyMagickWand (composite_wand);
				if (ret == MagickFalse)
					goto out;
			}
		}
		if (info->transformation == ODS_IMAGING_TRANSFORMATION_STRETCH) {
			ret = MagickThumbnailImage (magick_wand, info->width, info->height);
			if (ret == MagickFalse)
				goto out;
		}
	}

	/* encode image if needed */
	if (do_encode) {
		ret = MagickSetImageFormat (magick_wand, info->encoding);
		if (ret == MagickFalse)
			goto out;
	}

	/* write resized/encoded image to file */
	if (do_resize || do_encode) {
		GError	*error = NULL;
		gint	fd;

		fd = g_file_open_tmp (ODS_IMAGING_TEMPNAME,
		                      &(info->resized_image_filename), &error);
		if (fd == -1) {
			g_clear_error (&error);
			g_free (info->resized_image_filename);
			info->resized_image_filename = NULL;
			goto out;
		}
		close (fd);/* Do this roundtrip because MagickWriteImageFile is buggy */
		ret = MagickWriteImage (magick_wand, info->resized_image_filename);
		if (ret == MagickFalse) {
			g_free (info->resized_image_filename);
			info->resized_image_filename = NULL;
			goto out;
		}
		/* get resized image size */
		if (g_stat (info->resized_image_filename, &file_stat) == 0)
			info->size = file_stat.st_size;
	} else {
		/* no operations needed to be done, return original filename */
		info->resized_image_filename = g_strdup (info->filename);
	}

out:
	if (current_encoding)
		g_free (current_encoding);
	magick_wand = DestroyMagickWand (magick_wand);
	MagickWandTerminus ();

	g_idle_add ((GSourceFunc)ods_imaging_thread_callback, cb_data);
	g_message ("resize_image thread finished, adding callback to idle");
}

#endif /* USE_IMAGEMAGICK */

#ifdef USE_GDKPIXBUF

static char *
format_to_encoding (GdkPixbufFormat *format)
{
	char *name, *encoding;

	name = gdk_pixbuf_format_get_name (format);
	encoding = g_ascii_strup (name, -1);
	g_free (name);
	return encoding;
}

static const char *
encoding_to_pixbuf_format (const char *encoding)
{
	/* FIXME should we check the output of gdk_pixbuf_get_formats()
	 * and gdk_pixbuf_format_is_writable() instead? */
	if (strcmp (encoding, "JPEG") == 0)
		return "jpeg";
	if (strcmp (encoding, "PNG") == 0)
		return "png";
	if (strcmp (encoding, "BMP") == 0)
		return "bmp";
	return NULL;
}

static GdkPixbuf *
ods_imaging_pixbuf_new_with_format (const char *filename, char **encoding)
{
	GdkPixbuf *pixbuf;
	GMappedFile *file;
	GdkPixbufLoader *loader;
	GdkPixbufFormat *format;

	file = g_mapped_file_new (filename, FALSE, NULL);
	if (file == NULL)
		return NULL;

	loader = gdk_pixbuf_loader_new ();
	if (gdk_pixbuf_loader_write (loader,
	                             (guchar *) g_mapped_file_get_contents (file),
	                             g_mapped_file_get_length (file),
	                             NULL) == FALSE) {
		g_mapped_file_free (file);
		g_object_unref (loader);
		return NULL;
	}
	g_mapped_file_free (file);
	if (gdk_pixbuf_loader_close (loader, NULL) == FALSE) {
		g_object_unref (loader);
		return NULL;
	}

	format = gdk_pixbuf_loader_get_format (loader);
	*encoding = format_to_encoding (format);
	pixbuf = g_object_ref (gdk_pixbuf_loader_get_pixbuf (loader));
	g_object_unref (loader);

	return pixbuf;
}

static void
ods_imaging_get_image_info (OdsImagingCallbackData *cb_data)
{
	GdkPixbuf		*pixbuf;
	OdsImageInfo		*image_info;
	struct stat		file_stat;


	image_info = cb_data->data;
	g_type_init ();
	pixbuf = ods_imaging_pixbuf_new_with_format (image_info->filename,
	         &image_info->encoding);
	if (pixbuf == NULL)
		goto out;

	/* get info */
	image_info->width = gdk_pixbuf_get_width (pixbuf);
	image_info->height = gdk_pixbuf_get_height (pixbuf);
	if (g_stat (image_info->filename, &file_stat) == 0)
		image_info->size = file_stat.st_size;

	g_object_unref (pixbuf);
out:

	g_idle_add ((GSourceFunc)ods_imaging_thread_callback, cb_data);
}

static void
ods_imaging_resize_image (OdsImagingCallbackData *cb_data)
{
	OdsImageInfo			*info;
	GdkPixbuf			*pixbuf;
	gchar				*current_encoding = NULL;
	gulong				current_width = 0;
	gulong				current_height = 0;
	gboolean			do_resize;
	gboolean			do_encode;
	const char			*format;
	struct stat			file_stat;

	g_message("resize_image thread started");
	info = cb_data->data;
	g_type_init ();
	/* read the image */
	pixbuf = ods_imaging_pixbuf_new_with_format (info->filename, &current_encoding);
	if (pixbuf == NULL)
		goto out;

	/* get image info and determine what we need to do */
	current_width = gdk_pixbuf_get_width (pixbuf);
	current_height = gdk_pixbuf_get_height (pixbuf);
	do_encode = info->encoding && strcmp (info->encoding, current_encoding);
	format = encoding_to_pixbuf_format (info->encoding);
	if (format == NULL)
		goto out;
	do_resize = (info->width != current_width) ||
	            (info->height != current_height);

	/* resize image if needed */
	if (do_resize) {
		if (info->transformation == ODS_IMAGING_TRANSFORMATION_CROP) {
			/* Transformation CROP */
			if (info->width > current_width || info->height > current_height)
				info->transformation = ODS_IMAGING_TRANSFORMATION_STRETCH;
			else {
				GdkPixbuf *new;

				new = gdk_pixbuf_new_subpixbuf (pixbuf, 0, 0, info->width, info->height);
				g_object_unref (pixbuf);
				pixbuf = new;
			}
		} else if (info->transformation == ODS_IMAGING_TRANSFORMATION_FILL) {
			/* Transformation FILL */
			if (info->width < current_width || info->height < current_height)
				info->transformation = ODS_IMAGING_TRANSFORMATION_STRETCH;
			else {
				GdkPixbuf *blank, *new;

				blank = gdk_pixbuf_new (GDK_COLORSPACE_RGB, FALSE, 8, info->width, info->height);
				new = gdk_pixbuf_add_alpha (blank, FALSE, 0, 0, 0);
				g_object_unref (blank);
				gdk_pixbuf_fill (new, ODS_IMAGING_FILL_COLOR_RGBA);
				gdk_pixbuf_copy_area (pixbuf, 0, 0, current_width, current_height,
				                      new, 0, 0);

				g_object_unref (pixbuf);
				pixbuf = new;
			}
		}
		if (info->transformation == ODS_IMAGING_TRANSFORMATION_STRETCH) {
			GdkPixbuf *new;

			new = gdk_pixbuf_scale_simple (pixbuf, info->width, info->height, GDK_INTERP_BILINEAR);
			g_object_unref (pixbuf);
			pixbuf = new;
		}
	}

	/* write resized/encoded image to file */
	if (do_resize || do_encode) {
		GError	*error = NULL;
		gint	fd;

		fd = g_file_open_tmp (ODS_IMAGING_TEMPNAME,
		                      &(info->resized_image_filename), &error);
		if (fd == -1) {
			g_clear_error (&error);
			g_free (info->resized_image_filename);
			info->resized_image_filename = NULL;
			goto out;
		}
		close (fd);
		if (gdk_pixbuf_save (pixbuf, info->resized_image_filename, format, NULL, NULL) == FALSE) {
			g_free (info->resized_image_filename);
			info->resized_image_filename = NULL;
			goto out;
		}
		/* get resized image size */
		if (g_stat (info->resized_image_filename, &file_stat) == 0)
			info->size = file_stat.st_size;
	} else {
		/* no operations needed to be done, return original filename */
		info->resized_image_filename = g_strdup (info->filename);
	}

out:
	if (current_encoding)
		g_free (current_encoding);
	if (pixbuf != NULL)
		g_object_unref (pixbuf);

	g_idle_add ((GSourceFunc)ods_imaging_thread_callback, cb_data);
	g_message ("resize_image thread finished, adding callback to idle");
}
#endif /* USE_GDKPIXBUF */

gboolean
ods_imaging_get_image_info_async (const gchar *filename, OdsImagingFunc func,
                                  gpointer data)
{
#if defined(USE_IMAGEMAGICK) || defined(USE_GDKPIXBUF)
	OdsImageInfo			*image_info;
	OdsImagingCallbackData	*cb_data;

	image_info = g_new0 (OdsImageInfo, 1);
	image_info->filename = g_strdup (filename);

	cb_data = g_new0 (OdsImagingCallbackData, 1);
	cb_data->func = func;
	cb_data->data = image_info;
	cb_data->user_data = data;

	if (!g_thread_create ((GThreadFunc)ods_imaging_get_image_info,
	                      cb_data, FALSE, NULL)) {
		g_warning ("Thread creation failed");
		g_free (cb_data->data);
		g_free (cb_data);
		return FALSE;
	}
	return TRUE;
#else
	return FALSE;
#endif /* USE_IMAGEMAGICK || USE_GDKPIXBUF */
}

/* encoding can be NULL, otherwise it must be UPPERCASE
 * transformation can be 0 (no resizing done) */
gboolean
ods_imaging_resize_image_async (const gchar *filename, gulong width, gulong height,
                                const gchar *encoding, guint transformation,
                                OdsImagingFunc func, gpointer data)
{
#if defined(USE_IMAGEMAGICK) || defined (USE_GDKPIXBUF)
	OdsImageInfo			*image_info;
	OdsImagingCallbackData	*cb_data;

	g_message ("resize_image_async");
	image_info = g_new0 (OdsImageInfo, 1);
	image_info->filename = g_strdup (filename);
	image_info->width = width;
	image_info->height = height;
	if (encoding)
		image_info->encoding = g_strdup (encoding);
	image_info->transformation = transformation;


	cb_data = g_new0 (OdsImagingCallbackData, 1);
	cb_data->func = func;
	cb_data->data = image_info;
	cb_data->user_data = data;

	if (!g_thread_create ((GThreadFunc)ods_imaging_resize_image,
	                      cb_data, FALSE, NULL)) {
		g_warning ("Thread creation failed");
		g_free (cb_data->data);
		g_free (cb_data);
		return FALSE;
	}
	return TRUE;
#else
	return FALSE;
#endif /* USE_IMAGEMAGICK || USE_GDKPIXBUF */
}

gboolean
ods_imaging_make_image_thumbnail_async (const gchar *filename,
                                        OdsImagingFunc func, gpointer data)
{
	return ods_imaging_resize_image_async (filename,
	                                       ODS_IMAGING_THUMBNAIL_WIDTH, ODS_IMAGING_THUMBNAIL_HEIGHT,
	                                       ODS_IMAGING_THUMBNAIL_ENCODING,
	                                       ODS_IMAGING_TRANSFORMATION_STRETCH,
	                                       func, data);
}

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

#ifndef __ODS_ERROR_H
#define __ODS_ERROR_H

#include <glib-object.h>

G_BEGIN_DECLS

#define ODS_ERROR_DBUS_INTERFACE	"org.openobex.Error"

#define ODS_ERROR	 (ods_error_quark ())
#define ODS_TYPE_ERROR	 (ods_error_get_type ())

typedef enum {
	ODS_ERROR_INVALID_ARGUMENTS,
	ODS_ERROR_CONNECTION_ATTEMPT_FAILED,
	ODS_ERROR_NOT_SUPPORTED,
	ODS_ERROR_NOT_FOUND,
	ODS_ERROR_BUSY,
	ODS_ERROR_NOT_AUTHORIZED,
	ODS_ERROR_OUT_OF_MEMORY,
	ODS_ERROR_FAILED,
	ODS_ERROR_NOT_CONNECTED,
	ODS_ERROR_FORBIDDEN,
	ODS_ERROR_LINK_ERROR,
	ODS_ERROR_BAD_DATA,
	ODS_ERROR_STARTED,
	ODS_ERROR_NOT_STARTED,
	ODS_ERROR_TRANSPORT_NOT_AVAILABLE,
	ODS_ERROR_CONNECTION_REFUSED,
	ODS_ERROR_CONNECTION_TIMEOUT,
	ODS_ERROR_BAD_REQUEST,
	ODS_ERROR_NOT_IMPLEMENTED,
	ODS_ERROR_SERVER_ERROR,
	ODS_ERROR_TIMEOUT,
	ODS_ERROR_CANCELLED,
	ODS_ERROR_NOT_MODIFIED,
	ODS_ERROR_DATABASE_ERROR,
	ODS_ERROR_CONFLICT,
	ODS_ERROR_UNSUPPORTED_MEDIA_TYPE,
	ODS_ERROR_NO_FIFO_READER
} OdsError;


GQuark		 ods_error_quark			(void);
GType		 ods_error_get_type			(void);
void		 ods_error_err2gerror		(int err, GError **error);
void		 ods_error_obexrsp2gerror	(gint obex_response, GError **error);
gchar		*ods_error_get_dbus_name	(GError *error);

G_END_DECLS

#endif /* __ODS_ERROR_H */

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
#include <errno.h>
#include <string.h>

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "ods-error.h"

/**
 * ods_error_quark:
 * Return value: Our personal error quark.
 **/
GQuark
ods_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark) {
		quark = g_quark_from_static_string ("ods_error");
	}
	return quark;
}

/**
 * ods_error_get_type:
 **/
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }
GType
ods_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			ENUM_ENTRY (ODS_ERROR_INVALID_ARGUMENTS, "InvalidArguments"),
			ENUM_ENTRY (ODS_ERROR_CONNECTION_ATTEMPT_FAILED, "ConnectionAttemptFailed"),
			ENUM_ENTRY (ODS_ERROR_NOT_SUPPORTED, "NotSupported"),
			ENUM_ENTRY (ODS_ERROR_NOT_FOUND, "NotFound"),
			ENUM_ENTRY (ODS_ERROR_BUSY, "Busy"),
			ENUM_ENTRY (ODS_ERROR_NOT_AUTHORIZED, "NotAuthorized"),
			ENUM_ENTRY (ODS_ERROR_OUT_OF_MEMORY, "OutOfMemory"),
			ENUM_ENTRY (ODS_ERROR_FAILED, "Failed"), /* generic error */
			ENUM_ENTRY (ODS_ERROR_NOT_CONNECTED, "NotConnected"),
			ENUM_ENTRY (ODS_ERROR_FORBIDDEN, "Forbidden"),
			ENUM_ENTRY (ODS_ERROR_LINK_ERROR, "LinkError"),
			ENUM_ENTRY (ODS_ERROR_BAD_DATA, "BadData"),
			ENUM_ENTRY (ODS_ERROR_STARTED, "Started"),
			ENUM_ENTRY (ODS_ERROR_NOT_STARTED, "NotStarted"),
			ENUM_ENTRY (ODS_ERROR_TRANSPORT_NOT_AVAILABLE, "TransportNotAvailable"),
			ENUM_ENTRY (ODS_ERROR_CONNECTION_REFUSED, "ConnectionRefused"),
			ENUM_ENTRY (ODS_ERROR_CONNECTION_TIMEOUT, "ConnectionTimeout"),
			ENUM_ENTRY (ODS_ERROR_BAD_REQUEST, "BadRequest"),
			ENUM_ENTRY (ODS_ERROR_NOT_IMPLEMENTED, "NotImplemented"),
			ENUM_ENTRY (ODS_ERROR_SERVER_ERROR, "ServerError"),
			ENUM_ENTRY (ODS_ERROR_TIMEOUT, "Timeout"),
			ENUM_ENTRY (ODS_ERROR_CANCELLED, "Cancelled"),
			ENUM_ENTRY (ODS_ERROR_NOT_MODIFIED, "NotModified"),
			ENUM_ENTRY (ODS_ERROR_DATABASE_ERROR, "DatabaseError"),
			ENUM_ENTRY (ODS_ERROR_CONFLICT, "Conflict"),
			ENUM_ENTRY (ODS_ERROR_UNSUPPORTED_MEDIA_TYPE, "UnsupportedMediaType"),
			ENUM_ENTRY (ODS_ERROR_NO_FIFO_READER, "NoFifoReader"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("OdsError", values);
	}
	return etype;
}

void
ods_error_err2gerror (gint err, GError **error)
{
	if (!error)
		return;
	if (err < 0)
		err = -err;

	switch (err) {
		case EACCES:
			g_set_error (error, ODS_ERROR, ODS_ERROR_NOT_AUTHORIZED,
			             "Permission denied");
			break;
		case EBUSY:
			g_set_error (error, ODS_ERROR, ODS_ERROR_BUSY,
			             "Another operation in progress");
			break;
		case EINVAL:
			g_set_error (error, ODS_ERROR, ODS_ERROR_INVALID_ARGUMENTS,
			             "Invalid arguments");
			break;
		case ENOENT:
			g_set_error (error, ODS_ERROR, ODS_ERROR_NOT_FOUND,
			             "File not found");
			break;
		case ENOMEM:
			g_set_error (error, ODS_ERROR, ODS_ERROR_OUT_OF_MEMORY,
			             "Out of memory");
			break;
		case EPERM:
			g_set_error (error, ODS_ERROR, ODS_ERROR_FORBIDDEN,
			             "Operation forbidden");
			break;
		case ENOSPC:
			g_set_error (error, ODS_ERROR, ODS_ERROR_DATABASE_ERROR,
			             "No space left on device");
			break;
		case ENXIO:
			g_set_error (error, ODS_ERROR, ODS_ERROR_NO_FIFO_READER,
			             "No process has opened supplied FIFO for reading");
			break;
		default:
			g_set_error (error, ODS_ERROR, ODS_ERROR_FAILED,
			             "Unknown error occurred (errno: %d)", err);
			break;
	}
}

void
ods_error_obexrsp2gerror (gint obex_response, GError **error)
{
	if (!error)
		return;

	switch (obex_response) {
		case OBEX_RSP_REQUEST_TIME_OUT:
			g_set_error (error, ODS_ERROR, ODS_ERROR_TIMEOUT,
			             "Request timeout");
			break;
		case OBEX_RSP_BAD_REQUEST:
			g_set_error (error, ODS_ERROR, ODS_ERROR_BAD_REQUEST,
			             "Bad request");
			break;
		case OBEX_RSP_FORBIDDEN:
			g_set_error (error, ODS_ERROR, ODS_ERROR_FORBIDDEN,
			             "Operation forbidden");
			break;
		case OBEX_RSP_NOT_FOUND:
			g_set_error (error, ODS_ERROR, ODS_ERROR_NOT_FOUND,
			             "File not found");
			break;
		case OBEX_RSP_NOT_IMPLEMENTED:
			g_set_error (error, ODS_ERROR, ODS_ERROR_NOT_IMPLEMENTED,
			             "Not implemented");
			break;
		case OBEX_RSP_UNAUTHORIZED:
			g_set_error (error, ODS_ERROR, ODS_ERROR_NOT_AUTHORIZED,
			             "Not authorized");
			break;
		case OBEX_RSP_INTERNAL_SERVER_ERROR:
			g_set_error (error, ODS_ERROR, ODS_ERROR_SERVER_ERROR,
			             "Remote server error");
			break;
		case OBEX_RSP_NOT_MODIFIED:
			g_set_error (error, ODS_ERROR, ODS_ERROR_NOT_MODIFIED,
			             "No modification done");
			break;
		case OBEX_RSP_CONFLICT:
			g_set_error (error, ODS_ERROR, ODS_ERROR_CONFLICT,
			             "Conflict error");
			break;
		case OBEX_RSP_DATABASE_FULL:
			g_set_error (error, ODS_ERROR, ODS_ERROR_DATABASE_ERROR,
			             "Could not write (database full)");
			break;
		case OBEX_RSP_DATABASE_LOCKED:
			g_set_error (error, ODS_ERROR, ODS_ERROR_DATABASE_ERROR,
			             "Could not read/write (database locked)");
			break;
		case OBEX_RSP_UNSUPPORTED_MEDIA_TYPE:
			g_set_error (error, ODS_ERROR, ODS_ERROR_UNSUPPORTED_MEDIA_TYPE,
			             "Media type not supported");
			break;
		default:
			g_set_error (error, ODS_ERROR, ODS_ERROR_FAILED,
			             "Operation failed (unexpected response)");
			break;
	}
}

gchar *
ods_error_get_dbus_name	(GError *error)
{
	GEnumClass	*klass;
	GEnumValue	*value;
	const gchar	*error_name;

	klass = g_type_class_ref (ods_error_get_type ());
	value = g_enum_get_value (klass, error->code);
	g_type_class_unref (klass);
	error_name = value->value_nick;

	return g_strdup_printf ("%s.%s", ODS_ERROR_DBUS_INTERFACE, error_name);
}

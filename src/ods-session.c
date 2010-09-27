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

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>

#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>

#include <bluetooth/bluetooth.h>
#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "ods-bluez.h"
#include "ods-common.h"
#include "ods-error.h"
#include "ods-imaging-helpers.h"
#include "ods-manager.h"
#include "ods-marshal.h"
#include "ods-logging.h"
#include "ods-obex.h"
#include "ods-session.h"
#include "ods-session-dbus-glue.h"


static void     ods_session_finalize	(GObject		*object);
static void		ods_session_connect_internal (OdsSession *session,
        GError **error);

#define ODS_SESSION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), ODS_TYPE_SESSION, OdsSessionPrivate))

#define	ODS_SESSION_DBUS_PATH_PATTERN		"/org/openobex/session%d"
#define	ODS_SESSION_DBUS_INTERFACE			"org.openobex.Session"

typedef enum {
	ODS_SESSION_STATE_INIT,
	ODS_SESSION_STATE_OPEN,
	ODS_SESSION_STATE_BUSY,
	ODS_SESSION_STATE_NOT_CONNECTED
} OdsSessionState;

typedef struct OdsSessionPutImageData_ {
	OdsSession				*session;
	DBusGMethodInvocation	*context;
	gchar					*img_handle;
	gboolean				only_get_info;

} OdsSessionPutImageData;

struct OdsSessionPrivate {
	/* constructor properties */
	gint					fd; /* rfcomm device */
	guint					service;
	gchar					*owner; /* D-Bus client, who initiated this session */
	guchar					*target_uuid; /* Target UUID used for CMD_CONNECT */
	gint					usbintfnum; /* USB interface number */
	/* state variables */
	OdsSessionState			state; /* ODS_SESSION_STATE_INIT by default */
	/* OBEX connection */
	OdsObexContext			*obex_context;
	/* other */
	GStaticMutex			mutex;
	DBusGMethodInvocation	*dbus_context; /* D-Bus context for async methods */
	gchar					*dbus_path; /* D-Bus path for this object */
	gchar					*current_path; /* Current path on remote device */
	gchar					*new_path; /* Temporarily stored new path on remote device */
	gint					transfer_hint_fifo;
	gchar					*transfer_hint_name;
	gchar					*transfer_hint_type;
	guint64					transfer_hint_size;
	gint64					transfer_hint_mtime;
	gint64					transfer_hint_ctime;
	/* BIP-specific */
	guint					imaging_feature;
	ImagingSdpData			*imaging_sdp_data;
	gint					 protocol;
};

enum {
	CANCELLED,
	CONNECT_RESULT_INTERNAL,
	DISCONNECTED,
	CLOSED,
	TRANSFER_STARTED,
	TRANSFER_PROGRESS,
	TRANSFER_COMPLETED,
	ERROR_OCCURRED,
	IMAGE_HANDLE_RECEIVED,
	LAST_SIGNAL
};

static guint	signals [LAST_SIGNAL] = { 0, };
/* for numbering established sessions */
static guint	iterator = 0;

G_DEFINE_TYPE (OdsSession, ods_session, G_TYPE_OBJECT)


static void
session_log (OdsSession *session, GLogLevelFlags log_level, const gchar *message, ...)
{
	va_list args;
	gchar *format = NULL;
	
	va_start (args, message);
	if (session->priv->dbus_path) {
		format = g_strdup_printf("%s: %s", session->priv->dbus_path, message);
		g_logv (G_LOG_DOMAIN, log_level, format, args);
		g_free (format);
	}
	else {
		g_logv (G_LOG_DOMAIN, log_level, message, args);
	}
	va_end (args);
}

#define session_message(session, format, ...) session_log (session, G_LOG_LEVEL_MESSAGE, format, ##__VA_ARGS__)
#define session_warning(session, format, ...) session_log (session, G_LOG_LEVEL_WARNING, format, ##__VA_ARGS__)
#define ODS_SESSION_LOCK(session) session_log (session, G_LOG_LEVEL_MESSAGE, "LOCK %s", __FUNCTION__); g_static_mutex_lock (&(session)->priv->mutex)
#define ODS_SESSION_UNLOCK(session) session_log (session, G_LOG_LEVEL_MESSAGE, "UNLOCK %s", __FUNCTION__); g_static_mutex_unlock (&(session)->priv->mutex)

static void
emit_connect_result_internal (OdsSession *session, GError *error)
{
	gchar	*error_name;

	if (error) {
		ods_obex_close_transport (session->priv->obex_context);
		error_name = ods_error_get_dbus_name (error);
		g_signal_emit (session, signals [CONNECT_RESULT_INTERNAL], 0,
		               error_name, error->message);
		g_free (error_name);
	} else {
		g_signal_emit (session, signals [CONNECT_RESULT_INTERNAL], 0,
		               NULL, NULL);
	}
}

static gboolean
local_file_test (const gchar *local_path, gboolean *is_fifo)
{
	gboolean ret;

	/* Check if this is regular file or symlink pointing to regular file */
	ret = g_file_test (local_path, G_FILE_TEST_IS_REGULAR);
	/* Check if it is a FIFO */
	*is_fifo = FALSE;
	if (!ret) {
		struct stat s;

		if (g_stat (local_path, &s) == 0 && S_ISFIFO (s.st_mode)) {
			*is_fifo = TRUE;
			ret = TRUE;
		}
	}

	return ret;
}

static gboolean
emit_disconnected (OdsSession *session)
{
	ods_obex_close_transport (session->priv->obex_context);

	g_signal_emit (session, signals [DISCONNECTED], 0);
	return FALSE;
}

static gboolean
obex_io_callback (GIOChannel *io_channel, GIOCondition cond, gpointer data)
{
	obex_t		*obex_handle;
	OdsSession	*session;
	GError		*error = NULL;
	gboolean	ret = TRUE;

	obex_handle = (obex_t *) data;
	session = ODS_SESSION (OBEX_GetUserData (obex_handle));

	session_message (session, "obex_io callback");
	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		g_message("Lost connection000 %d,%d,%d,%d",cond,G_IO_ERR , G_IO_HUP, G_IO_NVAL);
		if (session->priv->state == ODS_SESSION_STATE_INIT) {
			/* Link error happened while establishing OBEX connection,
			 * hence emit ConnectResultInternal here (no need to emit
			 * Disconnected signal) */
			g_set_error (&error, ODS_ERROR, ODS_ERROR_LINK_ERROR,
			             "Lost connection");
			emit_connect_result_internal (session, error);
			g_clear_error (&error);
			return FALSE;
		}
		/* emit Disconnected for all other states */
		g_idle_add ((GSourceFunc) emit_disconnected, session);
		if (session->priv->state == ODS_SESSION_STATE_NOT_CONNECTED) {
			/* CMD_DISCONNECT was sent but did not receive proper reply,
			 * don't emit ErrorOccurred */
			return FALSE;
		}
		g_set_error (&error, ODS_ERROR, ODS_ERROR_LINK_ERROR, "Connection error");
		/* cleanup transfer data and set state to NOT_CONNECTED */
		/* If it was GET operation, remove incomplete file */
		if (session->priv->obex_context->obex_cmd == OBEX_CMD_GET &&
		        session->priv->obex_context->stream_fd >= 0)
			g_unlink (session->priv->obex_context->local);
		ods_obex_transfer_close (session->priv->obex_context);
		session->priv->state = ODS_SESSION_STATE_NOT_CONNECTED;
		/* Return D-Bus context, unlock mutex */
		if (session->priv->dbus_context) {
			dbus_g_method_return_error (session->priv->dbus_context, error);
			session->priv->dbus_context = NULL;
			ODS_SESSION_UNLOCK (session);
		}
		ret = FALSE;
	} else if (OBEX_HandleInput (obex_handle, 1) < 0) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_BAD_DATA,
		             "Could not parse incoming data");
	}

	if (error) {
		gchar *error_name;
		/* Get D-Bus name for error */
		error_name = ods_error_get_dbus_name (error);
		/* emit ErrorOccurred signal */
		g_signal_emit (session, signals [ERROR_OCCURRED], 0,
		               error_name, error->message);
		g_free (error_name);
		g_clear_error (&error);
	}

	return ret;
}

static void
reset_transfer_hints (OdsSession *session)
{
	session->priv->transfer_hint_fifo = -1;
	g_free (session->priv->transfer_hint_name);
	session->priv->transfer_hint_name = NULL;
	g_free (session->priv->transfer_hint_type);
	session->priv->transfer_hint_type = NULL;
	session->priv->transfer_hint_size = 0;
	session->priv->transfer_hint_mtime = -1;
	session->priv->transfer_hint_ctime = -1;
}

static void
obex_transfer_done (OdsSession *session, gint response)
{
	GError	*error = NULL;
	gchar	*error_name;

	session->priv->state = ODS_SESSION_STATE_OPEN;
	if (response != OBEX_RSP_SUCCESS && response != OBEX_RSP_PARTIAL_CONTENT) {
		/* get GError corresponding to OBEX response code */
		ods_error_obexrsp2gerror (response, &error);
		/* Get D-Bus name for error */
		error_name = ods_error_get_dbus_name (error);
		/* emit ErrorOccurred Signal */
		g_signal_emit (session, signals [ERROR_OCCURRED], 0,
		               error_name, error->message);
		g_free (error_name);
		g_clear_error (&error);
		return;
	}
	if (session->priv->obex_context->report_progress) {
		/* emit signals */
		g_signal_emit (session, signals [TRANSFER_PROGRESS], 0,
		               session->priv->obex_context->target_size);
		g_signal_emit (session, signals [TRANSFER_COMPLETED], 0);
	}
}

static void
obex_transfer_data_exchange_done (OdsSession *session, gint ret)
{
	GError			*error = NULL;
	gchar			*error_name;
	OdsObexContext	*obex_context;

	obex_context = session->priv->obex_context;
	if (ret < 0) {
		ods_error_err2gerror (ret, &error);
		/* Get D-Bus name for error */
		error_name = ods_error_get_dbus_name (error);
		/* emit ErrorOccurred Signal */
		g_signal_emit (session, signals [ERROR_OCCURRED], 0,
		               error_name, error->message);
		g_free (error_name);
		g_clear_error (&error);
		/* Reset state */
		session->priv->state = ODS_SESSION_STATE_OPEN;
	} else if (ret == 0 && obex_context->report_progress &&
	           !obex_context->transfer_started_signal_emitted) {
		g_signal_emit (session, signals [TRANSFER_STARTED], 0,
		               obex_context->remote,
		               obex_context->local,
		               obex_context->target_size);
		obex_context->transfer_started_signal_emitted = TRUE;
		g_message ("TransferStarted emitted at obex_transfer_data_exchange_done");
	}
}

static void
make_thumbnail_cb (OdsImageInfo *info, OdsSessionPutImageData *data)
{
	GError		*error = NULL;
	gchar		*error_name;
	gint		ret;

	if (!info->resized_image_filename) {
		/* Could not make thumbnail */
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "Could not make image thumbnail");
		goto out;
	}
	ret = ods_obex_put_linked_thumbnail (data->session->priv->obex_context,
	                                     info->resized_image_filename,
	                                     data->img_handle, info->size);
	if (ret < 0) {
		ods_error_err2gerror (ret, &error);
		goto out;
	}

out:
	if (error) {
		error_name = ods_error_get_dbus_name (error);
		/* emit ErrorOccurred Signal */
		g_signal_emit (data->session, signals [ERROR_OCCURRED], 0,
		               error_name, error->message);
		g_free (error_name);
		g_clear_error (&error);
		/* reset state */
		data->session->priv->state = ODS_SESSION_STATE_OPEN;
	}
	g_free (data->img_handle);
	g_free (data);
	ods_image_info_free (info);
}

static void
obex_request_done (OdsSession *session, obex_object_t *object, int command,
                   int response)
{
	GError			*error = NULL;
	OdsObexContext	*obex_context;
	/* for CMD_PUT only */
	obex_headerdata_t		hv;
	uint8_t					hi;
	guint					hlen;
	gchar					*img_handle = NULL;
	OdsSessionPutImageData	*cb_data;
	gchar					*error_name;
	gchar					*local_path = NULL;

	session_message (session, "obex_request_done: command %d, response %d (%s)",
					 command, response, OBEX_ResponseToString (response));

	obex_context = session->priv->obex_context;

	switch (command) {
		case OBEX_CMD_CONNECT:
			if (response == OBEX_RSP_SUCCESS) {
				ods_obex_connect_done (obex_context, object);
				/* update state */
				session->priv->state = ODS_SESSION_STATE_OPEN;
				emit_connect_result_internal (session, NULL);
			} else {
				g_set_error (&error, ODS_ERROR, ODS_ERROR_CONNECTION_REFUSED,
				             "Remote device refused connection");
				emit_connect_result_internal (session, error);
				g_clear_error (&error);
			}
			break;
		case OBEX_CMD_DISCONNECT:
			g_idle_add ((GSourceFunc) emit_disconnected, session);
			break;
		case OBEX_CMD_SETPATH:
			/* check response code here */
			if (response == OBEX_RSP_NOT_FOUND) {
				g_set_error (&error, ODS_ERROR, ODS_ERROR_NOT_FOUND,
				             "Path not found");
				if (session->priv->dbus_context) {
					dbus_g_method_return_error (session->priv->dbus_context,
					                            error);
					session->priv->dbus_context = NULL;
				}
				g_clear_error (&error);
			} else if (response == OBEX_RSP_SUCCESS) {
				gchar *temp;
				if (!strcmp (session->priv->new_path, ""))
					temp = g_strdup ("/");
				else if (!strcmp (session->priv->new_path, "..")) {
					gchar *temp2;
					/* get rid of trailing "/" */
					session->priv->current_path[
					    strlen (session->priv->current_path)-1] = 0;
					temp2 = g_path_get_dirname (session->priv->current_path);
					/* add trailing "/" */
					temp = g_strdup_printf ("%s/", temp2);
					g_free (temp2);
				} else {
					gchar *first_element;
					/* make sure we don't leave "/" in the beginning */
					if (session->priv->current_path[0] == '/')
						first_element = "";
					else
						first_element = session->priv->current_path;
					temp = g_strdup_printf ("%s%s/", first_element,
					                        session->priv->new_path);
				}
				g_free (session->priv->current_path);
				session->priv->current_path = temp;
				if (session->priv->dbus_context) {
					dbus_g_method_return (session->priv->dbus_context);
					session->priv->dbus_context = NULL;
				}
			} else {/* some other response code, must be error */
				/* get GError corresponding to OBEX response code */
				ods_error_obexrsp2gerror (response, &error);
				dbus_g_method_return_error (session->priv->dbus_context, error);
				session->priv->dbus_context = NULL;
				g_clear_error (&error);
			}
			ODS_SESSION_UNLOCK (session);
			break;
		case OBEX_CMD_ACTION:
			if (response == OBEX_RSP_SUCCESS) {
				if (session->priv->dbus_context) {
					dbus_g_method_return (session->priv->dbus_context);
					session->priv->dbus_context = NULL;
				}
			} else {
				/* get GError corresponding to OBEX response code */
				ods_error_obexrsp2gerror (response, &error);
				dbus_g_method_return_error (session->priv->dbus_context, error);
				session->priv->dbus_context = NULL;
				g_clear_error (&error);
			}
			ODS_SESSION_UNLOCK (session);
			break;
		case OBEX_CMD_PUT:
			if (!obex_context->report_progress) {
				/* DeleteRemoteFile or RemoteDisplay* was executed */
				session->priv->state = ODS_SESSION_STATE_OPEN;
				if (session->priv->dbus_context) {
					if (response != OBEX_RSP_SUCCESS) {
						/* get GError corresponding to OBEX response code */
						ods_error_obexrsp2gerror (response, &error);
						dbus_g_method_return_error (session->priv->dbus_context,
						                            error);
						session->priv->dbus_context = NULL;
						g_clear_error (&error);
					} else {
						dbus_g_method_return (session->priv->dbus_context);
						session->priv->dbus_context = NULL;
					}
					ODS_SESSION_UNLOCK (session);
				}
			} else {
				/* Check for img-handle header (in case of BIP PutImage) */
				while (OBEX_ObjectGetNextHeader(obex_context->obex_handle,
				                                object, &hi, &hv, &hlen)) {
					if (hi == OBEX_HDR_IMG_HANDLE) {
						img_handle = ods_filename_from_utf16 ((gchar *) hv.bs,
						                                      hlen);
						g_signal_emit (session, signals [IMAGE_HANDLE_RECEIVED],
						               0, img_handle, response==OBEX_RSP_PARTIAL_CONTENT);
						if (response == OBEX_RSP_PARTIAL_CONTENT) {
							/* save local_path */
							local_path = g_strdup (obex_context->local);
						}
					}
				}
				/* finish transfer (emit signals) */
				obex_transfer_done (session, response);
			}
			ods_obex_transfer_close (obex_context);
			if (img_handle && response==OBEX_RSP_PARTIAL_CONTENT) {
				/* Responder requested thumbnail, let's send it */
				session->priv->state = ODS_SESSION_STATE_BUSY;
				cb_data = g_new0 (OdsSessionPutImageData, 1);
				cb_data->session = session;
				cb_data->img_handle = g_strdup (img_handle);

				if (!ods_imaging_make_image_thumbnail_async (local_path,
				        (OdsImagingFunc)make_thumbnail_cb, cb_data)) {
					g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
					             "Could not create thread");
					error_name = ods_error_get_dbus_name (error);
					/* emit ErrorOccurred Signal */
					g_signal_emit (session, signals [ERROR_OCCURRED], 0,
					               error_name, error->message);
					g_free (error_name);
					g_clear_error (&error);
					g_free (cb_data->img_handle);
					g_free (cb_data);
					/* reset state */
					session->priv->state = ODS_SESSION_STATE_OPEN;
				}
			}
			if (img_handle)
				g_free (img_handle);
			if (local_path)
				g_free (local_path);
			break;
		case OBEX_CMD_GET:
			if (!obex_context->report_progress) {
				/* RetrieveFolderListing, GetCapability or GetImagingCapabilities
				 * was executed */
				session->priv->state = ODS_SESSION_STATE_OPEN;
				if (session->priv->dbus_context) {
					if (response != OBEX_RSP_SUCCESS) {
						/* get GError corresponding to OBEX response code */
						ods_error_obexrsp2gerror (response, &error);
						dbus_g_method_return_error (session->priv->dbus_context,
						                            error);
						session->priv->dbus_context = NULL;
						g_clear_error (&error);
					} else {
						gchar *buf;
						buf = g_strdup (ods_obex_get_buffer_as_string (obex_context));
						dbus_g_method_return (session->priv->dbus_context, buf);
						g_free (buf);
						session->priv->dbus_context = NULL;
					}
					ODS_SESSION_UNLOCK (session);
				}
			} else {
				obex_transfer_done (session, response);
				/* change modification time for received file */
				if (obex_context->local) {
					session_warning (session, "MODTIME: %d", (gint)obex_context->modtime);
					if (obex_context->modtime != -1) {
						struct utimbuf ubuf;
						ubuf.actime = time (NULL);
						ubuf.modtime = obex_context->modtime;
						if (utime (obex_context->local, &ubuf) < 0)
							session_warning (session, "Invalid modification time");
					}
				}
			}
			ods_obex_transfer_close (obex_context);
			break;
		case OBEX_CMD_SESSION:
			break;
	}
}

static void
obex_request_cancelled (OdsSession *session, OdsObexContext *obex_context)
{
	/* Cleanup transfer data and reset state */
	/* If it was GET operation, remove incomplete file */
	if (obex_context->obex_cmd == OBEX_CMD_GET &&
	        obex_context->stream_fd >= 0)
		g_unlink (obex_context->local);
	ods_obex_transfer_close (obex_context);
	session->priv->state = ODS_SESSION_STATE_OPEN;

	/* Emit Cancelled signal */
	g_message("obex_request_cancelled  emit signal CANCELLED");
	g_signal_emit (session, signals [CANCELLED], 0);

	/* In case this was trigerred by Cancel method */
	if (session->priv->dbus_context) {
		dbus_g_method_return (session->priv->dbus_context);
		session->priv->dbus_context = NULL;
		ODS_SESSION_UNLOCK (session);
	}
}

static void
obex_event (obex_t *handle, obex_object_t *object, int mode, int event,
            int command, int response)
{
	OdsSession		*session;
	OdsObexContext	*obex_context;
	gint			ret;

	g_message("obex_event()--%d--",event);
	session = ODS_SESSION (OBEX_GetUserData (handle));
	obex_context = session->priv->obex_context;
	ods_log_obex (session->priv->dbus_path, event, command, response);
	switch (event) {
		case OBEX_EV_PROGRESS:
			if (obex_context->report_progress) {
				g_signal_emit (session, signals [TRANSFER_PROGRESS], 0,
				               obex_context->counter);
				session_warning (session, "PROGRESS: %" G_GUINT64_FORMAT, obex_context->counter);
			}
			break;
		case OBEX_EV_REQHINT:
			OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_IMPLEMENTED, response);
			break;
		case OBEX_EV_REQ:
			OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_IMPLEMENTED, response);
			break;
		case OBEX_EV_REQDONE:
			obex_request_done (session, object, command, response);
			break;
		case OBEX_EV_PARSEERR:
			session_warning (session, "EV_PARSEERR");
			break;
		case OBEX_EV_ACCEPTHINT:
			session_warning (session, "EV_ACCEPTHINT");
			break;
		case OBEX_EV_LINKERR:
			/* we will get LINKERR when Cancel was called, but device didn't
			 * send OBEX_RSP_SUCCESS response (might be OBEX_RSP_BAD_REQUEST).
			 * When link error really happens, it is handled in io_callback */
			session_warning (session, "EV_LINKERR");
			/* go through to ABORT actions */
		case OBEX_EV_ABORT:
			session_message (session, "EV_ABORT");
			obex_request_cancelled (session, obex_context);
			break;
		case OBEX_EV_STREAMEMPTY:
			ret = ods_obex_writestream (obex_context, object);
			obex_transfer_data_exchange_done (session, ret);
			if (ret<0) 
				obex_request_cancelled (session, obex_context);
			break;
		case OBEX_EV_STREAMAVAIL:
			ret = ods_obex_readstream (obex_context, object);
			obex_transfer_data_exchange_done (session, ret);
			if (ret == 2) {
				/* Transfer was cancelled by sending RSP_FORBIDDEN, this will
				 * not trigger EV_ABORT so we need to emit Cancelled signal here */
				obex_request_cancelled (session, obex_context);
			}
			break;
		case OBEX_EV_UNEXPECTED:
		case OBEX_EV_REQCHECK:
			break;
	}
}

static void
obex_usbevent (obex_t *handle, obex_object_t *object, int mode, int event,
               int command, int response)
{
	OdsSession		*session;
	OdsObexContext	*ctxt;

	session = ODS_SESSION (OBEX_GetUserData (handle));
	ctxt = session->priv->obex_context;

	obex_event (handle, object, mode, event, command, response);
	if (event == OBEX_EV_PROGRESS ||
	        event == OBEX_EV_STREAMEMPTY ||
	        event == OBEX_EV_STREAMAVAIL)
		ctxt->usb_read_more = TRUE; /* There is more data to read */
	else
		ctxt->usb_read_more = FALSE;
}

static gboolean
ods_session_check_state (OdsSession *session, DBusGMethodInvocation *context)
{
	GError *error = NULL;

	/* check if connected */
	if (session->priv->state == ODS_SESSION_STATE_INIT ||
	        session->priv->state == ODS_SESSION_STATE_NOT_CONNECTED) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_NOT_CONNECTED,
		             "Not connected");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}
	/* check if busy */
	if (session->priv->state == ODS_SESSION_STATE_BUSY) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_BUSY,
		             "Another operation in progress");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}

	return TRUE;
}

static void
ods_session_set_property (GObject      *object,
                          guint         property_id,
                          const GValue *value,
                          GParamSpec   *pspec)
{
	OdsSession		*self = (OdsSession *) object;
	OdsObexContext	*obex_context = self->priv->obex_context;
	ImagingSdpData	*imaging_data;
	guchar			*target_uuid;
	GError			*error = NULL;

	switch (property_id) {
		case ODS_SESSION_FD:
			self->priv->fd = g_value_get_int (value);
			if (self->priv->fd >= 0) {
				if (ods_obex_setup_fdtransport (
				            obex_context, self->priv->fd,
				            ODS_DEFAULT_RX_MTU, ODS_DEFAULT_TX_MTU,
				            obex_event, obex_io_callback,
				            self, &error)) {
					/* connect automatically */
					ods_session_connect_internal (self, &error);
				}
				if (error) {
					emit_connect_result_internal (self, error);
					g_clear_error (&error);
				}
			}
			break;
		case ODS_SESSION_SERVICE:
			self->priv->service = g_value_get_int (value);
			break;
		case ODS_SESSION_OWNER:
			self->priv->owner = g_value_dup_string (value);
			break;
		case ODS_SESSION_IMAGING_FEATURE:
			self->priv->imaging_feature = g_value_get_int (value);
			break;
		case ODS_SESSION_IMAGING_SDP_DATA:
			imaging_data = g_value_get_pointer (value);
			self->priv->imaging_sdp_data = g_new0 (ImagingSdpData, 1);
			memcpy (self->priv->imaging_sdp_data, imaging_data,
			        sizeof (ImagingSdpData));
			break;
		case ODS_SESSION_TARGET_UUID:
			target_uuid = g_value_get_pointer (value);
			if (target_uuid) {
				self->priv->target_uuid = g_malloc0 (OBEX_UUID_LEN);
				memcpy (self->priv->target_uuid, target_uuid, OBEX_UUID_LEN);
			}
			break;
		case ODS_SESSION_USBINTFNUM:
			self->priv->usbintfnum = g_value_get_int (value);
			if (self->priv->usbintfnum >= 0) {
				if (ods_obex_setup_usbtransport (obex_context,
				                                 self->priv->usbintfnum, obex_usbevent,
				                                 obex_io_callback, self, &error)) {
					/* connect automatically */
					ods_session_connect_internal (self, &error);
				}
				if (error) {
					emit_connect_result_internal (self, error);
					g_clear_error (&error);
				}
			}
			break;
		default:
			/* We don't have any other property... */
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object,property_id,pspec);
			break;
	}
}

static void
ods_session_get_property (GObject      *object,
                          guint         property_id,
                          GValue       *value,
                          GParamSpec   *pspec)
{
	OdsSession *self = (OdsSession *) object;

	switch (property_id) {
		case ODS_SESSION_FD:
			g_value_set_int (value, self->priv->fd);
			break;
		case ODS_SESSION_SERVICE:
			g_value_set_int (value, self->priv->service);
			break;
		case ODS_SESSION_OWNER:
			g_value_set_string (value, self->priv->owner);
			break;
		case ODS_SESSION_DBUS_PATH:
			g_value_set_string (value, self->priv->dbus_path);
			break;
		case ODS_SESSION_IMAGING_FEATURE:
			g_value_set_int (value, self->priv->imaging_feature);
			break;
		case ODS_SESSION_IMAGING_SDP_DATA:
			g_value_set_pointer (value, self->priv->imaging_sdp_data);
			break;
		case ODS_SESSION_TARGET_UUID:
			g_value_set_pointer (value, self->priv->target_uuid);
			break;
		case ODS_SESSION_USBINTFNUM:
			g_value_set_int (value, self->priv->usbintfnum);
			break;
		default:
			/* We don't have any other property... */
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object,property_id,pspec);
			break;
	}
}

/**
 * ods_session_class_init:
 * @klass: The OdsSessionClass
 **/
static void
ods_session_class_init (OdsSessionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = ods_session_finalize;

	object_class->set_property = ods_session_set_property;
	object_class->get_property = ods_session_get_property;

	g_object_class_install_property (object_class,
	                                 ODS_SESSION_FD,
	                                 g_param_spec_int ("fd",
	                                                   "", "",
	                                                   -1, G_MAXINT, /* min, max values */
	                                                   0 /* default value */,
	                                                   G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SESSION_SERVICE,
	                                 g_param_spec_int ("service",
	                                                   "", "",
	                                                   0, G_MAXINT, /* min, max values */
	                                                   0 /* default value */,
	                                                   G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SESSION_OWNER,
	                                 g_param_spec_string ("owner",
	                                                      "", "",
	                                                      "" /* default value */,
	                                                      G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SESSION_DBUS_PATH,
	                                 g_param_spec_string ("dbus-path",
	                                                      "", "",
	                                                      "" /* default value */,
	                                                      G_PARAM_READABLE));

	g_object_class_install_property (object_class,
	                                 ODS_SESSION_IMAGING_FEATURE,
	                                 g_param_spec_int ("imaging-feature",
	                                                   "", "",
	                                                   0, G_MAXINT, /* min, max values */
	                                                   0 /* default value */,
	                                                   G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SESSION_IMAGING_SDP_DATA,
	                                 g_param_spec_pointer ("imaging-sdp-data",
	                                                       "", "",
	                                                       G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SESSION_TARGET_UUID,
	                                 g_param_spec_pointer ("target-uuid",
	                                                       "", "",
	                                                       G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));
	g_object_class_install_property (object_class,
	                                 ODS_SESSION_USBINTFNUM,
	                                 g_param_spec_int ("usbintfnum",
	                                                   "", "",
	                                                   G_MININT, G_MAXINT, /* min, max values */
	                                                   -1 /* default value */,
	                                                   G_PARAM_READWRITE));

	signals [CANCELLED] =
	    g_signal_new ("cancelled",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsSessionClass, cancelled),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);
	signals [CONNECT_RESULT_INTERNAL] =
	    g_signal_new ("connect-result-internal",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsSessionClass, connect_result_internal),
	                  NULL,
	                  NULL,
	                  ods_marshal_VOID__STRING_STRING,
	                  G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);

	signals [DISCONNECTED] =
	    g_signal_new ("disconnected",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsSessionClass, disconnected),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);
	signals [CLOSED] =
	    g_signal_new ("closed",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsSessionClass, closed),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);
	signals [TRANSFER_STARTED] =
	    g_signal_new ("transfer-started",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsSessionClass, transfer_started),
	                  NULL,
	                  NULL,
	                  ods_marshal_VOID__STRING_STRING_UINT64,
	                  G_TYPE_NONE, 3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT64);
	signals [TRANSFER_PROGRESS] =
	    g_signal_new ("transfer-progress",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsSessionClass, transfer_progress),
	                  NULL,
	                  NULL,
	                  ods_marshal_VOID__UINT64,
	                  G_TYPE_NONE, 1, G_TYPE_UINT64);
	signals [TRANSFER_COMPLETED] =
	    g_signal_new ("transfer-completed",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsSessionClass, transfer_completed),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);
	signals [ERROR_OCCURRED] =
	    g_signal_new ("error-occurred",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsSessionClass, error_occurred),
	                  NULL,
	                  NULL,
	                  ods_marshal_VOID__STRING_STRING,
	                  G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);
	signals [IMAGE_HANDLE_RECEIVED] =
	    g_signal_new ("image-handle-received",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsSessionClass, image_handle_received),
	                  NULL,
	                  NULL,
	                  ods_marshal_VOID__STRING_BOOLEAN,
	                  G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_BOOLEAN);

	g_type_class_add_private (klass, sizeof (OdsSessionPrivate));

	GError *error = NULL;

	/* Init the DBus connection, per-klass */
	klass->connection = dbus_g_bus_get (ODS_DBUS_BUS, &error);
	if (klass->connection == NULL) {
		g_warning("Unable to connect to dbus: %s", error->message);
		g_clear_error (&error);
		return;
	}

	/* &dbus_glib_ods_session_object_info is provided in the
	 * dbus/ods-session-dbus-glue.h file */
	dbus_g_object_type_install_info (ODS_TYPE_SESSION, &dbus_glib_ods_session_object_info);
}

/**
 * ods_session_init:
 * @session: This class instance
 **/
static void
ods_session_init (OdsSession *session)
{
	OdsSessionClass *klass = ODS_SESSION_GET_CLASS (session);
	session->priv = ODS_SESSION_GET_PRIVATE (session);

	/* initial priv values */
	session->priv->state = ODS_SESSION_STATE_INIT;
	session->priv->current_path = g_strdup ("/");
	session->priv->transfer_hint_fifo = -1;
	session->priv->transfer_hint_ctime = -1;
	session->priv->transfer_hint_mtime = -1;

	session->priv->obex_context = ods_obex_context_new ();

	/* figure out DBus object path for this instance */
	session->priv->dbus_path = g_strdup_printf (ODS_SESSION_DBUS_PATH_PATTERN,
	                           iterator);
	iterator++;

	/* create mutex */
	g_static_mutex_init (&session->priv->mutex);

	dbus_g_connection_register_g_object (klass->connection,
	                                     session->priv->dbus_path,
	                                     G_OBJECT (session));
}

/**
 * ods_session_finalize:
 * @object: The object to finalize
 *
 * Finalize the session
 **/
static void
ods_session_finalize (GObject *object)
{
	OdsSession *session;

	g_return_if_fail (object != NULL);
	g_return_if_fail (ODS_IS_SESSION (object));

	session = ODS_SESSION (object);

	g_return_if_fail (session->priv != NULL);

	/* close connection, free obex_context */
	ods_obex_close_transport (session->priv->obex_context);
	if (session->priv->fd != -1) {
		session_message (session, "closing connection");
		close (session->priv->fd);
	}
	OBEX_Cleanup (session->priv->obex_context->obex_handle);
	g_free (session->priv->obex_context);
	/* free other private variables */
	g_free (session->priv->owner);
	g_free (session->priv->dbus_path);
	g_free (session->priv->imaging_sdp_data);
	g_free (session->priv->target_uuid);
	if (session->priv->new_path)
		g_free (session->priv->new_path);
	g_free (session->priv->current_path);
	g_free (session->priv->transfer_hint_name);
	g_free (session->priv->transfer_hint_type);
	g_static_mutex_free (&session->priv->mutex);

	G_OBJECT_CLASS (ods_session_parent_class)->finalize (object);
}

/**
 * ods_session_new:
 *
 * Return value: a new OdsSession object.
 **/
OdsSession *
ods_session_new (gint fd, gint usb_interface_number, gint service,
                 const gchar *owner,
                 const gchar *target_uuid)
{
	OdsSession *session;
	session = g_object_new (ODS_TYPE_SESSION,
	                        "fd", fd,
	                        "usbintfnum", usb_interface_number,
	                        "service", service,
	                        "owner", owner,
	                        "target-uuid", target_uuid,
	                        NULL);
	return ODS_SESSION (session);
}

static void
ods_session_connect_internal (OdsSession *session, GError **error)
{
	guchar	*uuid = NULL;
	guint	uuid_length = 0;
	gint	ret;


	if (session->priv->state != ODS_SESSION_STATE_INIT)
		return;

	if (session->priv->target_uuid) {
		uuid = session->priv->target_uuid;
		uuid_length = OBEX_UUID_LEN;
	}

	/* send obex connect command */
	ret = ods_obex_connect (session->priv->obex_context, uuid, uuid_length);
	if (ret < 0)
		ods_error_err2gerror (ret, error);
}

gint
ods_session_disconnect_internal (OdsSession *session, GError **error)
{
	gint ret;

	if (session->priv->state == ODS_SESSION_STATE_NOT_CONNECTED) {
		/* emit DISCONNECTED signal now */
		g_idle_add ((GSourceFunc) emit_disconnected, session);
		return 1;
	}

	/* actually disconnect */
	session->priv->state = ODS_SESSION_STATE_NOT_CONNECTED;
	ret = ods_obex_disconnect (session->priv->obex_context);
	if (ret < 0) {
		/* emit DISCONNECTED signal now and set state to NOT_CONNECTED
		 * in this case disconnection will happen when socket is closed */
		g_idle_add ((GSourceFunc) emit_disconnected, session);

		ods_error_err2gerror (ret, error);
		return -1;
	}

	return 0;
}

gboolean
ods_session_disconnect (OdsSession *session, DBusGMethodInvocation *context)
{
	gint	ret;
	GError	*error = NULL;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->state == ODS_SESSION_STATE_INIT)
		g_set_error (&error, ODS_ERROR, ODS_ERROR_NOT_AUTHORIZED,
		             "Session is still being connected, Cancel connection instead");
	else if (session->priv->state == ODS_SESSION_STATE_BUSY)
		g_set_error (&error, ODS_ERROR, ODS_ERROR_BUSY,
		             "Operations in progress need to be cancelled first");
	if (error) {
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	ret = ods_session_disconnect_internal (session, &error);
	if (ret == -1) {
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
	} else {
		dbus_g_method_return (context);
		ODS_SESSION_UNLOCK (session);
	}

	return TRUE;
}

gboolean
ods_session_close (OdsSession *session, DBusGMethodInvocation *context)
{
	GError *error = NULL;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->state == ODS_SESSION_STATE_INIT)
		g_set_error (&error, ODS_ERROR, ODS_ERROR_NOT_AUTHORIZED,
		             "Session is still being connected, Cancel connection instead");
	else if (session->priv->state != ODS_SESSION_STATE_NOT_CONNECTED)
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "Need to disconnect first");
	if (error) {
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	/* emit CLOSED signal; manager will finalize this object */
	ODS_SESSION_UNLOCK (session);
	g_signal_emit (session, signals[CLOSED], 0);
	dbus_g_method_return (context);
	return TRUE;
}

void
ods_session_set_protocol (OdsSession *session, gint protocol)
{
	if((protocol!=RFCOMM_OBEX)&&(protocol!=L2CAP_OBEX))
		protocol = RFCOMM_OBEX;
	
	g_message ("ods_session_set_protocol --%d--",protocol);
	session->priv->obex_context->protocol = protocol;
}
static gboolean
ods_session_setpath (OdsSession *session, const gchar *path, gboolean create,
                     DBusGMethodInvocation *context)
{
	gint			ret;
	GError			*error = NULL;
	OdsObexContext	*obex_context = session->priv->obex_context;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->service != ODS_SERVICE_GOEP &&
	        session->priv->service != ODS_SERVICE_FTP) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected profile");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!ods_session_check_state (session, context)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	/* validate path */
	if (strchr (path, '/')) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid character in path ('/')");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	if (session->priv->dbus_context) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "DBus context is set (this is probably a bug)");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	/* set dbus context */
	session->priv->dbus_context = context;
	/* copy new path to temporary variable */
	if (session->priv->new_path)
		g_free (session->priv->new_path);
	session->priv->new_path = g_strdup (path);

	/* change the folder */
	ret = ods_obex_setpath (obex_context, path, create);
	if (ret < 0) {
		ods_error_err2gerror(ret, &error);
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		/* reset state */
		session->priv->dbus_context = NULL;
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	return TRUE;
}

gboolean
ods_session_change_current_folder (OdsSession *session, const gchar *path,
                                   DBusGMethodInvocation *context)
{
	return ods_session_setpath (session, path, FALSE, context);
}

gboolean
ods_session_change_current_folder_backward (OdsSession *session,
        DBusGMethodInvocation *context)
{
	return ods_session_setpath (session, "..", FALSE, context);
}

gboolean
ods_session_change_current_folder_to_root (OdsSession *session,
        DBusGMethodInvocation *context)
{
	return ods_session_setpath (session, "", FALSE, context);
}

gchar *
ods_session_get_current_path (OdsSession *session)
{
	return g_strdup (session->priv->current_path);
}

static gboolean
ods_session_copy_remote_file_full (OdsSession *session,
                                   const gchar *remote_filename,
                                   const gchar *type,
                                   const gchar *local_path,
                                   DBusGMethodInvocation *context)
{
	gint		ret;
	GError		*error = NULL;
	gboolean	is_fifo;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->service != ODS_SERVICE_GOEP &&
	        session->priv->service != ODS_SERVICE_OPP &&
	        session->priv->service != ODS_SERVICE_FTP) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected profile");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!ods_session_check_state (session, context)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	/* validate remote_filename */
	if (remote_filename &&
	        (*remote_filename == '\0' || strchr (remote_filename, '/'))) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid remote filename");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}
	/* validate type */
	if (type && *type == '\0') {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid type");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}
	/* validate local path */
	if (*local_path == '\0') {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid local path");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}
	local_file_test (local_path, &is_fifo); /* non existent path is also OK, it'll be created */

	session->priv->state = ODS_SESSION_STATE_BUSY;
	ret = ods_obex_get (session->priv->obex_context, local_path,
	                    remote_filename, type, is_fifo);
	if (ret < 0) {
		ods_error_err2gerror (ret, &error);
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		/* reset state */
		session->priv->state = ODS_SESSION_STATE_OPEN;
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	/* return immediately, user will get transfer progress and completion signals */
	dbus_g_method_return (context);
	ODS_SESSION_UNLOCK (session);
	return TRUE;
}

gboolean
ods_session_copy_remote_file (OdsSession *session,
                              const gchar *remote_filename,
                              const gchar *local_path,
                              DBusGMethodInvocation *context)
{
	return ods_session_copy_remote_file_full (session, remote_filename, NULL,
	        local_path, context);
}

gboolean
ods_session_copy_remote_file_by_type (OdsSession *session,
                                      const gchar *type,
                                      const gchar *local_path,
                                      DBusGMethodInvocation *context)
{
	return ods_session_copy_remote_file_full (session, NULL, type,
	        local_path, context);
}

gboolean
ods_session_create_folder (OdsSession *session,
                           const gchar *folder_name,
                           DBusGMethodInvocation *context)
{
	return ods_session_setpath (session, folder_name, TRUE, context);
}

static gboolean
ods_session_get_by_type (OdsSession *session, DBusGMethodInvocation *context,
                         const gchar *type)
{
	gint	ret;
	GError	*error = NULL;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!ods_session_check_state (session, context)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->dbus_context) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "DBus context is set (this is probably a bug)");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	/* set dbus context */
	session->priv->dbus_context = context;

	session->priv->state = ODS_SESSION_STATE_BUSY;
	ret = ods_obex_get (session->priv->obex_context, NULL, NULL, type, FALSE);
	if (ret < 0) {
		ods_error_err2gerror (ret, &error);
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		session->priv->dbus_context = NULL;
		/* reset state */
		session->priv->state = ODS_SESSION_STATE_OPEN;
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	return TRUE;
}

gboolean
ods_session_retrieve_folder_listing (OdsSession *session,
                                     DBusGMethodInvocation *context)
{
	GError *error = NULL;

	if (session->priv->service != ODS_SERVICE_FTP) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected profile");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}
	return ods_session_get_by_type (session, context, LST_TYPE);
}

gboolean
ods_session_get_capability (OdsSession *session, DBusGMethodInvocation *context)
{
	GError *error = NULL;

	if (session->priv->service != ODS_SERVICE_FTP) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected profile");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}
	return ods_session_get_by_type (session, context, CAP_TYPE);
}

gboolean
ods_session_get_imaging_capabilities (OdsSession *session,
                                      DBusGMethodInvocation *context)
{
	GError *error = NULL;

	if (session->priv->service != ODS_SERVICE_BIP) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected profile");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}
	return ods_session_get_by_type (session, context, BIP_CAPABILITIES_TYPE);
}

gboolean
ods_session_send_file_ext (OdsSession *session, const gchar *local_path,
                           const gchar *remote_filename, const gchar *type,
                           DBusGMethodInvocation *context)
{
	gint		ret;
	gchar		*basename = NULL;
	const gchar	*remote_used = NULL;
	const gchar	*type_used = NULL;
	GError		*error = NULL;
	gboolean	is_fifo;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->service != ODS_SERVICE_GOEP &&
	        session->priv->service != ODS_SERVICE_OPP &&
	        session->priv->service != ODS_SERVICE_FTP) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected profile");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!ods_session_check_state (session, context)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!local_file_test (local_path, &is_fifo)) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid local path");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}

	/* Figure out if we have to use different remote_filename and type */
	if (*remote_filename != '\0') {
		g_free (session->priv->transfer_hint_name);
		session->priv->transfer_hint_name = g_strdup (remote_filename);
	}
	if (session->priv->transfer_hint_name)
		remote_used = session->priv->transfer_hint_name;
	else {
		basename = g_path_get_basename (local_path);
		remote_used = basename;
	}
	if (*type != '\0') {
		g_free (session->priv->transfer_hint_type);
		session->priv->transfer_hint_type = g_strdup (type);
	}
	if (session->priv->transfer_hint_type)
		type_used = session->priv->transfer_hint_type;

	session->priv->state = ODS_SESSION_STATE_BUSY;
	ret = ods_obex_put (session->priv->obex_context, local_path,
	                    remote_used, type_used,
	                    session->priv->transfer_hint_size,
	                    session->priv->transfer_hint_mtime,
	                    is_fifo, session->priv->transfer_hint_fifo);
	g_free (basename);
	reset_transfer_hints (session);

	if (ret < 0) {
		ods_error_err2gerror (ret, &error);
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		/* reset state */
		session->priv->state = ODS_SESSION_STATE_OPEN;
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	/* return immediately, user will get transfer progress and completion signals */
	dbus_g_method_return (context);
	ODS_SESSION_UNLOCK (session);
	return TRUE;
}

gboolean
ods_session_send_file (OdsSession *session,
                       const gchar *local_path,
                       DBusGMethodInvocation *context)
{
	return ods_session_send_file_ext (session, local_path, "", "", context);
}

gboolean
ods_session_set_transfer_hints (OdsSession *session,
                                const gchar *fifo,
                                const gchar *remote_filename,
                                const gchar *type, guint64 size,
                                gint64 mtime, gint64 ctime,
                                DBusGMethodInvocation *context)
{
	GError *error = NULL;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	/* Cleanup old data */
	if (session->priv->transfer_hint_fifo >= 0)
		close (session->priv->transfer_hint_fifo);
	reset_transfer_hints (session);
	/* Set transfer hints */
	if (*fifo != '\0') {
		session->priv->transfer_hint_fifo = open (fifo, O_RDONLY | O_NONBLOCK);
		if (session->priv->transfer_hint_fifo < 0) {
			ods_error_err2gerror (errno, &error);
			dbus_g_method_return_error (context, error);
			g_clear_error (&error);
			ODS_SESSION_UNLOCK (session);
			return FALSE;
		}
	}
	if (*remote_filename != '\0')
		session->priv->transfer_hint_name = g_strdup (remote_filename);
	if (*type != '\0')
		session->priv->transfer_hint_type = g_strdup (type);
	session->priv->transfer_hint_size = size;
	session->priv->transfer_hint_mtime = mtime;
	session->priv->transfer_hint_ctime = ctime;

	dbus_g_method_return (context);
	ODS_SESSION_UNLOCK (session);
	return TRUE;
}

gboolean
ods_session_delete_remote_file (OdsSession *session,
                                const gchar *remote_filename,
                                DBusGMethodInvocation *context)
{
	gint	ret;
	GError	*error = NULL;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->service != ODS_SERVICE_FTP) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected profile");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!ods_session_check_state (session, context)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (*remote_filename == '\0' || strchr (remote_filename, '/')) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid remote filename");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->dbus_context) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "DBus context is set (this is probably a bug)");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	/* set dbus context */
	session->priv->dbus_context = context;
	session->priv->state = ODS_SESSION_STATE_BUSY;
	ret = ods_obex_put (session->priv->obex_context, NULL,
	                    remote_filename, NULL, 0, -1, FALSE, -1);
	if (ret < 0) {
		ods_error_err2gerror (ret, &error);
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		session->priv->dbus_context = NULL;
		/* reset state */
		session->priv->state = ODS_SESSION_STATE_OPEN;
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	return TRUE;
}

static gboolean
ods_session_remote_action (OdsSession *session,
                           const gchar *remote_source,
                           const gchar *remote_destination,
                           guint8 action, DBusGMethodInvocation *context)
{
	gint			ret;
	GError			*error = NULL;
	OdsObexContext	*obex_context = session->priv->obex_context;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->service != ODS_SERVICE_GOEP &&
	        session->priv->service != ODS_SERVICE_FTP) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected profile");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!ods_session_check_state (session, context)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	/* validate remote_source */
	if (strchr (remote_source, '/')) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid character in remote_source ('/')");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	if (session->priv->dbus_context) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "DBus context is set (this is probably a bug)");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	/* set dbus context */
	session->priv->dbus_context = context;

	/* do selected action */
	ret = ods_obex_action (obex_context, remote_source,
	                       remote_destination, action, 0);
	if (ret < 0) {
		ods_error_err2gerror(ret, &error);
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		/* reset state */
		session->priv->dbus_context = NULL;
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	return TRUE;
}

gboolean
ods_session_remote_copy (OdsSession *session,
                         const gchar *remote_source,
                         const gchar *remote_destination,
                         DBusGMethodInvocation *context)
{
	return ods_session_remote_action (session, remote_source,
	                                  remote_destination, OBEX_ACTION_COPY,
	                                  context);
}

gboolean
ods_session_remote_move (OdsSession *session,
                         const gchar *remote_source,
                         const gchar *remote_destination,
                         DBusGMethodInvocation *context)
{
	return ods_session_remote_action (session, remote_source,
	                                  remote_destination, OBEX_ACTION_MOVE,
	                                  context);
}

static void
get_image_info_cb (OdsImageInfo *info, OdsSessionPutImageData *data)
{
	GError		*error = NULL;
	gchar		*basename;
	gchar		*pixel_str;
	const gchar	*transformation_str;
	gint		ret;

	if (!info->encoding) {
		/* Could not acquire image info */
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "Could not acquire image info");
		dbus_g_method_return_error (data->context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (data->session);
		goto out;
	}
	if (data->only_get_info) {
		dbus_g_method_return (data->context, info->width, info->height,
		                      g_strdup (info->encoding));
		ODS_SESSION_UNLOCK (data->session);
		goto out;
	}
	basename = g_path_get_basename (info->filename);
	pixel_str = ods_imaging_get_pixel_string (info->width, info->height);
	transformation_str = ods_imaging_get_transformation_string (
	                         info->transformation);
	ret = ods_obex_put_image (data->session->priv->obex_context, info->filename,
	                          basename, info->encoding, pixel_str,
	                          info->size, transformation_str);
	g_free (basename);
	g_free (pixel_str);
	if (ret < 0) {
		ods_error_err2gerror (ret, &error);
		dbus_g_method_return_error (data->context, error);
		g_clear_error (&error);
		/* reset state */
		data->session->priv->state = ODS_SESSION_STATE_OPEN;
		ODS_SESSION_UNLOCK (data->session);
		goto out;
	}

	dbus_g_method_return (data->context);
	ODS_SESSION_UNLOCK (data->session);

out:
	g_free (data);
	ods_image_info_free (info);
}

gboolean
ods_session_get_image_info (OdsSession *session, const gchar *local_path,
                            DBusGMethodInvocation *context)
{
	GError					*error = NULL;
	OdsSessionPutImageData	*cb_data;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!g_file_test (local_path, G_FILE_TEST_IS_REGULAR)) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid local path");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	cb_data = g_new0 (OdsSessionPutImageData, 1);
	cb_data->session = session;
	cb_data->context = context;
	cb_data->only_get_info = TRUE;
	if (!ods_imaging_get_image_info_async (local_path,
	                                       (OdsImagingFunc)get_image_info_cb, cb_data)) {
#ifdef USE_IMAGEMAGICK
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "Could not create thread");
#else
		g_set_error (&error, ODS_ERROR, ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported (ImageMagick support disabled)");
#endif
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		g_free (cb_data);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	return TRUE;
}

gboolean
ods_session_put_image (OdsSession *session,
                       const gchar *local_path,
                       DBusGMethodInvocation *context)
{
	GError					*error = NULL;
	OdsSessionPutImageData	*cb_data;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->service != ODS_SERVICE_BIP) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected profile");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->imaging_feature != BIP_SUPP_FEAT_IMAGE_PUSH &&
	        session->priv->imaging_feature != BIP_SUPP_FEAT_REMOTE_DISPLAY) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected imaging feature");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!ods_session_check_state (session, context)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!g_file_test (local_path, G_FILE_TEST_IS_REGULAR)) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid local path");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	session->priv->state = ODS_SESSION_STATE_BUSY;
	cb_data = g_new0 (OdsSessionPutImageData, 1);
	cb_data->session = session;
	cb_data->context = context;
	if (!ods_imaging_get_image_info_async (local_path,
	                                       (OdsImagingFunc)get_image_info_cb, cb_data)) {
#ifdef USE_IMAGEMAGICK
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "Could not create thread");
#else
		g_set_error (&error, ODS_ERROR, ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported (ImageMagick support disabled)");
#endif
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		g_free (cb_data);
		/* reset state */
		session->priv->state = ODS_SESSION_STATE_OPEN;
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	return TRUE;
}

static void
resize_image_cb (OdsImageInfo *info, OdsSessionPutImageData *data)
{
	GError		*error = NULL;
	gchar		*basename;
	gchar		*pixel_str;
	const gchar	*transformation_str;
	gint		ret;

	session_message (data->session, "resize_image_cb");
	if (!info->resized_image_filename) {
		/* Could not acquire image info */
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "Could not resize/encode image");
		dbus_g_method_return_error (data->context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (data->session);
		goto out;
	}
	basename = g_path_get_basename (info->filename);
	pixel_str = ods_imaging_get_pixel_string (info->width, info->height);
	transformation_str = ods_imaging_get_transformation_string (
	                         info->transformation);
	ret = ods_obex_put_image (data->session->priv->obex_context,
	                          info->resized_image_filename,
	                          basename, info->encoding, pixel_str,
	                          info->size, transformation_str);
	g_free (basename);
	g_free (pixel_str);
	if (ret < 0) {
		ods_error_err2gerror (ret, &error);
		dbus_g_method_return_error (data->context, error);
		g_clear_error (&error);
		/* reset state */
		data->session->priv->state = ODS_SESSION_STATE_OPEN;
		ODS_SESSION_UNLOCK (data->session);
		goto out;
	}

	dbus_g_method_return (data->context);
	ODS_SESSION_UNLOCK (data->session);

out:
	g_free (data);
	ods_image_info_free (info);
}

gboolean
ods_session_put_image_resized (OdsSession *session, const gchar *local_path,
                               guint16 width, guint16 height,
                               const gchar *encoding,
                               const gchar *transformation,
                               DBusGMethodInvocation *context)
{
	GError					*error = NULL;
	OdsSessionPutImageData	*cb_data;
	const gchar				*encoding_local;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->service != ODS_SERVICE_BIP) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected profile");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->imaging_feature != BIP_SUPP_FEAT_IMAGE_PUSH &&
	        session->priv->imaging_feature != BIP_SUPP_FEAT_REMOTE_DISPLAY) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected imaging feature");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!ods_session_check_state (session, context)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!g_file_test (local_path, G_FILE_TEST_IS_REGULAR)) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid local path");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	session->priv->state = ODS_SESSION_STATE_BUSY;
	cb_data = g_new0 (OdsSessionPutImageData, 1);
	cb_data->session = session;
	cb_data->context = context;
	if (*encoding == '\0')
		encoding_local = NULL;
	else
		encoding_local = encoding;
	if (!ods_imaging_resize_image_async (local_path, width, height,
	                                     encoding, ods_imaging_get_transformation (transformation),
	                                     (OdsImagingFunc)resize_image_cb, cb_data)) {
#ifdef USE_IMAGEMAGICK
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "Could not create thread");
#else
		g_set_error (&error, ODS_ERROR, ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported (ImageMagick support disabled)");
#endif
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		g_free (cb_data);
		/* reset state */
		session->priv->state = ODS_SESSION_STATE_OPEN;
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	return TRUE;
}

gboolean
ods_session_put_linked_attachment (OdsSession *session,
                                   const gchar *image_handle,
                                   const gchar *local_path,
                                   const gchar *content_type,
                                   const gchar *charset,
                                   DBusGMethodInvocation *context)
{
	GError	*error = NULL;
	const gchar *remote_used;
	gchar	*basename = NULL;
	gint	ret;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->service != ODS_SERVICE_BIP) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected profile");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->imaging_feature != BIP_SUPP_FEAT_IMAGE_PUSH) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected imaging feature");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!(session->priv->imaging_sdp_data->supp_functions &
	        BIP_SUPP_FUNC_PUT_LINKED_ATTACHMENT)) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by remote device");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!ods_session_check_state (session, context)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!g_file_test (local_path, G_FILE_TEST_IS_REGULAR)) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid local path");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (*image_handle == '\0') {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid image handle");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	if (session->priv->transfer_hint_name)
		remote_used = session->priv->transfer_hint_name;
	else {
		basename = g_path_get_basename (local_path);
		remote_used = basename;
	}
	session->priv->state = ODS_SESSION_STATE_BUSY;
	ret = ods_obex_put_linked_attachment (session->priv->obex_context,
	                                      local_path, image_handle, remote_used,
	                                      content_type, charset, 0, -1);
	g_free (basename);
	reset_transfer_hints (session);

	if (ret < 0) {
		ods_error_err2gerror (ret, &error);
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		/* reset state */
		session->priv->state = ODS_SESSION_STATE_OPEN;
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	dbus_g_method_return (context);
	ODS_SESSION_UNLOCK (session);
	return TRUE;
}

static gboolean
ods_session_remote_display_full (OdsSession *session,
                                 const gchar *image_handle,
                                 guint8 action,
                                 DBusGMethodInvocation *context)
{
	gint	ret;
	GError	*error = NULL;

	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->service != ODS_SERVICE_BIP) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected profile");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->imaging_feature != BIP_SUPP_FEAT_REMOTE_DISPLAY) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_NOT_SUPPORTED,
		             "Function not supported by selected imaging feature");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (!ods_session_check_state (session, context)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (action == BIP_REMOTEDISPLAY_SELECTIMAGE && *image_handle == '\0') {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid image handle");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	if (session->priv->dbus_context) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "DBus context is set (this is probably a bug)");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	/* set dbus context */
	session->priv->dbus_context = context;
	session->priv->state = ODS_SESSION_STATE_BUSY;
	ret = ods_obex_remote_display (session->priv->obex_context, image_handle,
	                               action);
	if (ret < 0) {
		ods_error_err2gerror (ret, &error);
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		session->priv->dbus_context = NULL;
		/* reset state */
		session->priv->state = ODS_SESSION_STATE_OPEN;
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}
	/* will actually return when we get REQ_DONE */
	return TRUE;
}

gboolean
ods_session_remote_display_select_image (OdsSession *session,
        const gchar *image_handle,
        DBusGMethodInvocation *context)
{
	return ods_session_remote_display_full (session, image_handle,
	                                        BIP_REMOTEDISPLAY_SELECTIMAGE,
	                                        context);
}

gboolean
ods_session_remote_display_show_current_image (OdsSession *session,
        DBusGMethodInvocation *context)
{
	return ods_session_remote_display_full (session, "",
	                                        BIP_REMOTEDISPLAY_CURRENTIMAGE,
	                                        context);
}

gboolean
ods_session_remote_display_show_next_image (OdsSession *session,
        DBusGMethodInvocation *context)
{
	return ods_session_remote_display_full (session, "",
	                                        BIP_REMOTEDISPLAY_NEXTIMAGE,
	                                        context);
}

gboolean
ods_session_remote_display_show_previous_image (OdsSession *session,
        DBusGMethodInvocation *context)
{
	return ods_session_remote_display_full (session, "",
	                                        BIP_REMOTEDISPLAY_PREVIOUSIMAGE,
	                                        context);
}

GHashTable *
ods_session_get_transfer_info (OdsSession *session)
{
	return ods_obex_transfer_get_info (session->priv->obex_context);
}

gboolean
ods_session_is_busy (OdsSession *session)
{
	/* check for any operation (except transfers) */
	if (!g_static_mutex_trylock (&session->priv->mutex))
		return TRUE;
	else
		g_static_mutex_unlock (&session->priv->mutex);
	/* check for transfers */
	return (session->priv->state == ODS_SESSION_STATE_BUSY);
}

gboolean
ods_session_cancel_internal (OdsSession *session)
{
	OdsObexContext *ctxt = session->priv->obex_context;

	if (session->priv->state != ODS_SESSION_STATE_BUSY) {
		/* emit CANCELLED signal now */
		g_message("ods_session_cancel_internal emit signal CANCELLED");
		g_signal_emit (session, signals[CANCELLED], 0);
		return FALSE;
	}
	OBEX_CancelRequest (ctxt->obex_handle, TRUE); 
	ctxt->cancelled = TRUE;  

	return TRUE;
}

gboolean
ods_session_cancel (OdsSession *session, DBusGMethodInvocation *context)
{
	g_message("-----------------------ods_session_cancel--------------------");
	ODS_SESSION_LOCK (session);
	/* do checks */
	if (!ods_check_caller (context, session->priv->owner)) {
		ODS_SESSION_UNLOCK (session);
		return FALSE;
	}

	if (ods_session_cancel_internal (session)) {
		if (session->priv->dbus_context) {
			GError *error;

			g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
			             "DBus context is set (this is probably a bug)");
			dbus_g_method_return_error (context, error);
			g_clear_error (&error);
			ODS_SESSION_UNLOCK (session);
			return FALSE;
		}
		/* set dbus context */
		session->priv->dbus_context = context;
		/* will return at obex_event{EV_ABORT} */
	} else {
		dbus_g_method_return (context);
		ODS_SESSION_UNLOCK (session);
	}
	return TRUE;
}

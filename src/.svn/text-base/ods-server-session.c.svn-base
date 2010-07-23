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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>

#include <bluetooth/bluetooth.h>
#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "ods-common.h"
#include "ods-error.h"
#include "ods-marshal.h"
#include "ods-logging.h"
#include "ods-obex.h"
#include "ods-server-session.h"
#include "ods-server-session-dbus-glue.h"


static void     ods_server_session_finalize		(GObject		*object);

#define ODS_SERVER_SESSION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), ODS_TYPE_SERVER_SESSION, OdsServerSessionPrivate))

#define ODS_SERVER_SESSION_LOCK(server_session) g_message ("LOCK %s", __FUNCTION__); g_static_mutex_lock (&(server_session)->priv->mutex)
#define ODS_SERVER_SESSION_UNLOCK(server_session) g_message ("UNLOCK %s", __FUNCTION__); g_static_mutex_unlock (&(server_session)->priv->mutex)

#define	ODS_SERVER_SESSION_DBUS_PATH_PATTERN	"/org/openobex/serversession%d"
#define	ODS_SERVER_SESSION_DBUS_INTERFACE		"org.openobex.ServerSession"

typedef enum {
	ODS_SERVER_SESSION_STATE_NOT_CONNECTED,
	ODS_SERVER_SESSION_STATE_OPEN,
	ODS_SERVER_SESSION_STATE_BUSY
} OdsServerSessionState;


struct OdsServerSessionPrivate {
	/* constructor properties */
	gint					fd; /* rfcomm device */
	guint					service;
	gchar					*root_path; /* root folder (constructor "path" property) */
	gchar					*path; /* current path */
	gchar					*owner; /* D-Bus client, who initiated this session */
	gboolean				allow_write; /* Whether to allow changes in file system */
	gboolean				auto_accept; /* Whether incoming files should be auto-accepted */
	gboolean				require_imaging_thumbnails;/* whether to request thumbnail after PutImage is completed */
	/* other properties */
	gboolean				using_tty;/* if we are using tty device */
	/* state (open or busy) */
	OdsServerSessionState	state; /* ODS_SERVER_SESSION_STATE_OPEN by default */
	/* OBEX connection */
	OdsObexContext			*obex_context;
	/* other */
	GStaticMutex			mutex;
	DBusGMethodInvocation	*dbus_context; /* D-Bus context for async methods */
	gchar					*dbus_path; /* D-Bus path for this object */
	/* BIP-specific */
	GHashTable				*img_handle_list;/* hash list associating image handles with real filenames */
	guint					selected_img;/* selected image handle (for RemoteDisplay functions) */
};

enum {
	CANCELLED,
	DISCONNECTED,
	TRANSFER_STARTED,
	TRANSFER_PROGRESS,
	TRANSFER_COMPLETED,
	ERROR_OCCURRED,
	REMOTE_DISPLAY_REQUESTED,
	LAST_SIGNAL
};

static guint	signals [LAST_SIGNAL] = { 0, };
/* for numbering established sessions */
static guint	iterator = 0;

G_DEFINE_TYPE (OdsServerSession, ods_server_session, G_TYPE_OBJECT)

/* This is to be called from mainloop, not directly. It's to ensure
 * that we don't finalize this object from within itself. */
static gboolean
emit_disconnected (OdsServerSession *server_session)
{
	ods_obex_close_transport (server_session->priv->obex_context);
	g_signal_emit (server_session, signals [DISCONNECTED], 0);
	return FALSE;
}

/* adds uploaded image to list and returns it's image handle */
static const gchar*
image_list_add (OdsServerSession *server_session, const gchar *filename)
{
	gchar *img_handle;

	if (!server_session->priv->img_handle_list) {
		server_session->priv->img_handle_list = g_hash_table_new_full (
		                                            g_str_hash, g_str_equal,
		                                            g_free, g_free);
	}
	img_handle = g_strdup_printf ("%07u",
	                              g_hash_table_size (server_session->priv->img_handle_list)+1);
	g_hash_table_insert (server_session->priv->img_handle_list, img_handle,
	                     g_strdup (filename));
	return img_handle;
}

static void
remote_display_action (OdsServerSession *server_session, guint8 action)
{
	OdsServerSessionPrivate	*priv;
	gchar					*img_handle = NULL;
	gchar					*filename;

	priv = server_session->priv;
	if (action == 0)
		return;

	switch (action) {
		case BIP_REMOTEDISPLAY_NEXTIMAGE:
			if (priv->selected_img < g_hash_table_size (priv->img_handle_list))
				priv->selected_img++;
			break;
		case BIP_REMOTEDISPLAY_PREVIOUSIMAGE:
			if (priv->selected_img > 1)
				priv->selected_img--;
			break;
		case BIP_REMOTEDISPLAY_SELECTIMAGE:
			priv->selected_img = atoi (priv->obex_context->img_handle);
			if (priv->selected_img > g_hash_table_size (priv->img_handle_list) ||
			        priv->selected_img < 1) {
				/* resort to first */
				priv->selected_img = 1;
			} else {
				/* valid value, use this img_handle */
				img_handle = g_strdup (priv->obex_context->img_handle);
			}
			break;
		case BIP_REMOTEDISPLAY_CURRENTIMAGE:
			break;
		default:
			g_message ("Invalid RemoteDisplay action specified");
			return;
	}
	if (!img_handle) {
		/* get img_handle from selected_img */
		img_handle = g_strdup_printf ("%07u", priv->selected_img);
	}
	/* lookup filename for selected img_handle */
	if (!(filename = g_hash_table_lookup (priv->img_handle_list, img_handle))) {
		/* should never happen since we did all bounds checking */
		g_warning ("Selected img_handle not found in img_handle_list");
		return;
	}
	/* finally emit RemoteDisplayRequested */
	g_signal_emit (server_session, signals [REMOTE_DISPLAY_REQUESTED], 0,
	               filename);
	g_free (img_handle);
}

static gboolean
obex_io_callback (GIOChannel *io_channel, GIOCondition cond, gpointer data)
{
	obex_t				*obex_handle;
	OdsServerSession	*server_session;
	GError				*error = NULL;
	gboolean			ret = TRUE;

	obex_handle = (obex_t *) data;
	server_session = ODS_SERVER_SESSION (OBEX_GetUserData (obex_handle));

	g_message ("io callback");
	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_LINK_ERROR, "Connection error");
		/* cleanup transfer data */
		ods_obex_transfer_close (server_session->priv->obex_context);
		server_session->priv->state = ODS_SERVER_SESSION_STATE_NOT_CONNECTED;
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
		g_signal_emit (server_session, signals [ERROR_OCCURRED], 0,
		               error_name, error->message);
		g_free (error_name);
		g_clear_error (&error);
	}
	if (!ret) {
		/* Also emit DISCONNECTED signal, since this session is now defunct */
		g_idle_add ((GSourceFunc) emit_disconnected, server_session);
	}

	return ret;
}

static void
obex_transfer_data_exchange_done (OdsServerSession *server_session, gint ret)
{
	GError			*error = NULL;
	gchar			*error_name;
	OdsObexContext	*obex_context;

	obex_context = server_session->priv->obex_context;
	if (ret < 0) {
		ods_error_err2gerror (ret, &error);
		/* Get D-Bus name for error */
		error_name = ods_error_get_dbus_name (error);
		/* emit ErrorOccurred Signal */
		g_signal_emit (server_session, signals [ERROR_OCCURRED], 0,
		               error_name, error->message);
		g_free (error_name);
		g_clear_error (&error);
		/* Reset state */
		server_session->priv->state = ODS_SERVER_SESSION_STATE_OPEN;
	} else if (ret == 0 && !obex_context->transfer_started_signal_emitted &&
	           obex_context->report_progress && obex_context->local) {
		g_signal_emit (server_session, signals [TRANSFER_STARTED], 0,
		               obex_context->remote,
		               obex_context->local,
		               obex_context->target_size);
		obex_context->transfer_started_signal_emitted = TRUE;
		g_message ("TransferStarted emitted at obex_transfer_data_exchange_done");
	}
}

static void
send_image_handle (OdsServerSession *server_session, OdsObexContext *obex_context,
                   obex_object_t *object)
{
	/* In the end of BIP PutImage request ImageHandle has to be sent
	 * Make sure that we have transfer info (PUT request was received).
	 * This might be called on last readstream but REQCHECK event
	 * might not have happened yet (happens with small files). */
	const gchar			*img_handle;
	gchar				*uhandle = NULL;
	gsize				uhandle_len = 0;
	obex_headerdata_t	hv;
	gint				ret;

	if (server_session->priv->service == ODS_SERVICE_BIP &&
	        obex_context->obex_cmd == OBEX_CMD_PUT && obex_context->local &&
	        !g_ascii_strncasecmp (obex_context->type, BIP_IMG_TYPE,
	                              strlen (obex_context->type))) {

		img_handle = image_list_add (server_session, obex_context->local);
		uhandle_len = ods_filename_to_utf16 (&uhandle, img_handle);
		if (uhandle == NULL) {
			g_warning ("Failed to convert img_handle");
			return;
		}
		hv.bs = (guchar *)uhandle;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_IMG_HANDLE, hv,
		                            uhandle_len, 0);
		g_free (uhandle);
		if (ret < 0) {
			g_warning ("Failed to add header");
			return;
		}
		if (server_session->priv->require_imaging_thumbnails)
			OBEX_ObjectSetRsp (object, OBEX_RSP_PARTIAL_CONTENT, OBEX_RSP_PARTIAL_CONTENT);
		else
			OBEX_ObjectSetRsp (object, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
	}
}

static void
obex_request_cancelled (OdsServerSession *server_session, OdsObexContext *obex_context)
{
	/* Cleanup transfer stuff and reset state */
	/* If it was PUT operation, remove incomplete file */
	if (obex_context->obex_cmd == OBEX_CMD_PUT &&
	        obex_context->stream_fd >= 0)
		g_unlink (obex_context->local);
	ods_obex_transfer_close (obex_context);
	server_session->priv->state = ODS_SERVER_SESSION_STATE_OPEN;
	/* emit CANCELLED signal */
	g_signal_emit (server_session, signals [CANCELLED], 0);

	/* In case this was trigerred by Cancel method */
	if (server_session->priv->dbus_context) {
		dbus_g_method_return (server_session->priv->dbus_context);
		server_session->priv->dbus_context = NULL;
		ODS_SERVER_SESSION_UNLOCK (server_session);
	}
}

static gint
obex_suspend_request (OdsServerSession *server_session, OdsObexContext *obex_context)
{
	/* only suspend if TransferStarted signal was already emitted */
	if (!server_session->priv->auto_accept &&
	        obex_context->transfer_started_signal_emitted &&
	        !obex_context->suspend_result) {
		ods_obex_transfer_suspend (obex_context);

		if (obex_context->suspend_result == OBEX_SUSP_REJECTED)
			ods_server_session_cancel_internal (server_session);
		return obex_context->suspend_result;
	}
	return 0;
}

static void
obex_request_put (OdsServerSession *server_session, OdsObexContext *obex_context,
                  obex_object_t *object)
{
	guint8		action = 0;/* only used for BIP RemoteDisplay*/
	gint		ret, suspend_ret;
	gboolean	no_response_on_success = FALSE;
	gchar		*img_filename;

	/* Check if we already have all transfer info
	* because both EV_REQCHECK and EV_REQ trigger this function */
	if (obex_context->stream_fd >= 0)
		return;

	if (!server_session->priv->allow_write) {
		g_message ("CMD_PUT forbidden");
		OBEX_ObjectSetRsp (object, OBEX_RSP_FORBIDDEN,
		                   OBEX_RSP_FORBIDDEN);
		return;
	}
	/* Check if we have write permissions for current path */
	if (g_access (server_session->priv->path, W_OK) < 0) {
		g_message ("No write permissions for current path");
		OBEX_ObjectSetRsp (object, OBEX_RSP_UNAUTHORIZED,
		                   OBEX_RSP_UNAUTHORIZED);
		return;
	}
	/* If auto_accept is False and transfer hasn't been suspended yet,
	 * we will not send response until the transfer is accepted or rejected */
	if (!server_session->priv->auto_accept && !obex_context->suspend_result)
		no_response_on_success = TRUE;
	ret = ods_obex_srv_put (obex_context, object,
	                        server_session->priv->path, &action, no_response_on_success);
	g_message ("ret=%d", ret);
	/* Add ImageFilename to ExtInfo according to ImageHandle (for BIP) */
	if (ret == 0 && obex_context->img_handle) {
		img_filename = g_hash_table_lookup (server_session->priv->img_handle_list,
		                                    obex_context->img_handle);
		if (!img_filename)
			g_message ("Invalid ImgHandle received");
		else
			ods_obex_transfer_add_info (obex_context, "ImageFilename",
			                            g_strdup (img_filename));
	}
	/* Process BIP RemoteDisplay info (if available) */
	if (ret == 0)
		remote_display_action (server_session, action);
	/* also emit TransferStarted signal */
	if (ret == 0 && !obex_context->transfer_started_signal_emitted &&
	        obex_context->report_progress && obex_context->local) {
		g_signal_emit (server_session, signals [TRANSFER_STARTED],
		               0, obex_context->remote,
		               obex_context->local,
		               obex_context->target_size);
		obex_context->transfer_started_signal_emitted = TRUE;
		g_message ("TransferStarted emitted at obex_request_put");
	}
	/* In a rare situation when received file is smaller than MTU,
	 * this function is called after all data is already received.
	 * We have to suspend request if auto_accept is False;
	 * For BIP, image handle has to be sent as well */
	if (ret == 0) {
		suspend_ret = obex_suspend_request (server_session, obex_context);
		if (suspend_ret == OBEX_SUSP_REJECTED) {
			/* Transfer was rejected and no more data will be received so we
			 * delete written file, emit Cancelled signal and send RSP_FORBIDDEN */
			obex_request_cancelled (server_session, obex_context);
			OBEX_ObjectSetRsp (object, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		} else if (suspend_ret == OBEX_SUSP_ACCEPTED) {
			/* Transfer was accepted, send RSP_SUCCESS */
			OBEX_ObjectSetRsp (object, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
		}
		if (suspend_ret != OBEX_SUSP_REJECTED) {
			/* Transfer was accepted either now or earlier */
			send_image_handle (server_session, obex_context, object);
		}
	}
}

static void
obex_event (obex_t *handle, obex_object_t *object, int mode, int event,
            int command, int response)
{
	OdsServerSession	*server_session;
	OdsObexContext		*obex_context;
	gchar				*new_path;
	gint				ret;

	server_session = ODS_SERVER_SESSION (OBEX_GetUserData (handle));
	obex_context = server_session->priv->obex_context;
	ods_log_obex (server_session->priv->dbus_path, event, command, response);

	switch (event) {
		case OBEX_EV_PROGRESS:
			if (obex_context->report_progress) {
				g_signal_emit (server_session, signals [TRANSFER_PROGRESS], 0,
				               obex_context->counter);
			}
			break;
		case OBEX_EV_LINKERR:
			/* we will get LINKERR when Cancel was called, but device didn't
			 * send OBEX_RSP_SUCCESS response (might be OBEX_RSP_BAD_REQUEST).
			 * When link error really happens, it is handled in io_callback */
			g_warning ("EV_LINKERR");
		case OBEX_EV_ABORT:
			obex_request_cancelled (server_session, obex_context);
			break;
		case OBEX_EV_REQDONE:
			switch (command) {
				case OBEX_CMD_DISCONNECT:
					ods_server_session_disconnect_internal (server_session);
					break;
				case OBEX_CMD_PUT:
					/* Transfer complete */
					ods_obex_transfer_close (obex_context);
					server_session->priv->state = ODS_SERVER_SESSION_STATE_OPEN;
					if (obex_context->report_progress)
						g_signal_emit (server_session, signals [TRANSFER_COMPLETED], 0);
					break;
				case OBEX_CMD_GET:
					/* Transfer complete */
					ods_obex_transfer_close (obex_context);
					server_session->priv->state = ODS_SERVER_SESSION_STATE_OPEN;
					if (obex_context->report_progress)
						g_signal_emit (server_session, signals [TRANSFER_COMPLETED], 0);
					break;
				default:
					break;
			}
			break;
		case OBEX_EV_REQHINT:
			switch (command) {
				case OBEX_CMD_PUT:
					OBEX_ObjectReadStream (handle, object, NULL);
					obex_context->obex_cmd = OBEX_CMD_PUT;
					/* Initialize transfer and set state */
					ods_obex_transfer_new (obex_context, NULL, NULL, NULL);
					server_session->priv->state = ODS_SERVER_SESSION_STATE_BUSY;

					OBEX_ObjectSetRsp (object, OBEX_RSP_CONTINUE,
					                   OBEX_RSP_SUCCESS);
					break;
				case OBEX_CMD_GET:
					obex_context->obex_cmd = OBEX_CMD_GET;
					/* Initialize transfer and set state */
					ods_obex_transfer_new (obex_context, NULL, NULL, NULL);
					server_session->priv->state = ODS_SERVER_SESSION_STATE_BUSY;

					OBEX_ObjectSetRsp (object, OBEX_RSP_CONTINUE,
					                   OBEX_RSP_SUCCESS);
					break;
				case OBEX_CMD_CONNECT:
				case OBEX_CMD_DISCONNECT:
				case OBEX_CMD_SETPATH:
					OBEX_ObjectSetRsp (object, OBEX_RSP_CONTINUE,
					                   OBEX_RSP_SUCCESS);
					break;
				default:
					OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_IMPLEMENTED,
					                   OBEX_RSP_NOT_IMPLEMENTED);
					break;
			}
			break;
		case OBEX_EV_REQCHECK:
			if (command == OBEX_CMD_PUT) {
				g_message ("CMD_PUT requested at REQCHECK");
				obex_request_put (server_session, obex_context, object);
			}
			break;
		case OBEX_EV_REQ:
			switch (command) {
				case OBEX_CMD_DISCONNECT:
					OBEX_ObjectSetRsp(object, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
					break;

				case OBEX_CMD_CONNECT:
					g_message ("CMD_CONNECT requested");
					ods_obex_srv_connect (obex_context, object, server_session->priv->service);
					break;

				case OBEX_CMD_SETPATH:
					if (server_session->priv->service == ODS_SERVICE_OPP) {
						OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_IMPLEMENTED,
						                   OBEX_RSP_NOT_IMPLEMENTED);
						return;
					}
					g_message ("CMD_SETPATH requested");
					g_message ("current path: %s", server_session->priv->path);
					g_message ("root path: %s", server_session->priv->root_path);
					if (ods_obex_srv_setpath (obex_context, object,
					                          server_session->priv->root_path,
					                          server_session->priv->path,
					                          &new_path)) {
						g_free (server_session->priv->path);
						server_session->priv->path = new_path;
					}
					g_message ("new path: %s", server_session->priv->path);
					break;
				case OBEX_CMD_GET:
					g_message ("CMD_GET requested");
					ret = ods_obex_srv_get (obex_context, object,
					                        server_session->priv->path,
					                        server_session->priv->root_path,
					                        server_session->priv->allow_write);
					g_message ("ret=%d", ret);
					if (ret > 0 && obex_context->report_progress) {
						g_signal_emit (server_session, signals [TRANSFER_STARTED],
						               0, obex_context->remote,
						               obex_context->local,
						               obex_context->target_size);
						obex_context->transfer_started_signal_emitted = TRUE;
						g_message ("TransferStarted emitted at obex_event at OBEX_EV_REQ");
					}
					break;
				case OBEX_CMD_PUT:
					g_message ("CMD_PUT requested");
					obex_request_put (server_session, obex_context, object);
					break;
				default:
					OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_IMPLEMENTED,
					                   OBEX_RSP_NOT_IMPLEMENTED);
					break;
			}
			break;
		case OBEX_EV_STREAMEMPTY:
			ret = ods_obex_writestream (obex_context, object);
			obex_transfer_data_exchange_done (server_session, ret);
			break;
		case OBEX_EV_STREAMAVAIL:
			ret = 0;

			if (!server_session->priv->allow_write) {
				g_message ("CMD_PUT forbidden");
				OBEX_ObjectSetRsp (object, OBEX_RSP_FORBIDDEN,
				                   OBEX_RSP_FORBIDDEN);
				/* We don't emit ErrorOccurred for this situation */
				return;
			}
			/* Check if we have write permissions for current path */
			if (g_access (server_session->priv->path, W_OK) < 0) {
				OBEX_ObjectSetRsp (object, OBEX_RSP_UNAUTHORIZED,
				                   OBEX_RSP_UNAUTHORIZED);
				ret = -EACCES;
				goto readstream_done;
			}
			/* This PUT request is definitely not a delete request. Let's
			 * open a file for writing in case this wasn't done yet */
			if (obex_context->remote && !obex_context->local) {
				if (!ods_obex_srv_new_file (obex_context, server_session->priv->path)) {
					OBEX_ObjectSetRsp (object, OBEX_RSP_UNAUTHORIZED,
					                   OBEX_RSP_UNAUTHORIZED);
					ret = -EACCES;
					goto readstream_done;
				}
			}
			/* suspend request if necessary */
			obex_suspend_request (server_session, obex_context);
			ret = ods_obex_readstream (obex_context, object);
readstream_done:
			obex_transfer_data_exchange_done (server_session, ret);
			if (ret == 2) {
				/* Transfer was cancelled by sending RSP_FORBIDDEN, this will
				 * not trigger EV_ABORT so we need to emit Cancelled signal here */
				obex_request_cancelled (server_session, obex_context);
			} else if (ret == 1) {
				/* Last packet was received, send image handle */
				send_image_handle (server_session, obex_context, object);
			}
			break;
		case OBEX_EV_PARSEERR:
			/* Handled in io_callback */
			break;
		case OBEX_EV_UNEXPECTED:
			break;
		default:
			break;
	}
}

static void
ods_server_session_set_property (GObject      *object,
                                 guint         property_id,
                                 const GValue *value,
                                 GParamSpec   *pspec)
{
	OdsServerSession *self = ODS_SERVER_SESSION (object);

	switch (property_id) {
		case ODS_SERVER_SESSION_FD:
			self->priv->fd = g_value_get_int (value);
			if (self->priv->fd >= 0) {
				OdsObexContext *obex_context = self->priv->obex_context;
				GError *error = NULL;
				guint16 rx_mtu = ODS_DEFAULT_RX_MTU;
				guint16 tx_mtu = ODS_DEFAULT_TX_MTU;

				g_message ("Creating server session");
				if (self->priv->using_tty) {
					rx_mtu = ODS_TTY_RX_MTU;
					tx_mtu = ODS_TTY_TX_MTU;
				}
				ods_obex_setup_fdtransport (obex_context,
				                            self->priv->fd, rx_mtu, tx_mtu,
				                            obex_event, obex_io_callback,
				                            self, &error);
				if (error) {
					g_warning ("Error while creating server session: %s",
					           error->message);
					ods_server_session_disconnect_internal (self);
					g_clear_error (&error);
				}
			}
			break;
		case ODS_SERVER_SESSION_SERVICE:
			self->priv->service = g_value_get_int (value);
			break;
		case ODS_SERVER_SESSION_PATH:
			self->priv->root_path = g_value_dup_string (value);
			self->priv->path = g_value_dup_string (value);
			g_warning ("Session path: %s", self->priv->path);
			break;
		case ODS_SERVER_SESSION_ALLOW_WRITE:
			self->priv->allow_write = g_value_get_boolean (value);
			break;
		case ODS_SERVER_SESSION_AUTO_ACCEPT:
			self->priv->auto_accept = g_value_get_boolean (value);
			break;
		case ODS_SERVER_SESSION_REQUIRE_IMAGING_THUMBNAILS:
			self->priv->require_imaging_thumbnails = g_value_get_boolean (value);
			break;
		case ODS_SERVER_SESSION_USING_TTY:
			self->priv->using_tty = g_value_get_boolean (value);
			break;
		case ODS_SERVER_SESSION_OWNER:
			self->priv->owner = g_value_dup_string (value);
			break;
		default:
			/* We don't have any other property... */
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object,property_id,pspec);
			break;
	}
}

static void
ods_server_session_get_property (GObject      *object,
                                 guint         property_id,
                                 GValue       *value,
                                 GParamSpec   *pspec)
{
	OdsServerSession *self = ODS_SERVER_SESSION (object);

	switch (property_id) {
		case ODS_SERVER_SESSION_FD:
			g_value_set_int (value, self->priv->fd);
			break;
		case ODS_SERVER_SESSION_SERVICE:
			g_value_set_int (value, self->priv->service);
			break;
		case ODS_SERVER_SESSION_PATH:
			g_value_set_string (value, self->priv->path);
			break;
		case ODS_SERVER_SESSION_ALLOW_WRITE:
			g_value_set_boolean (value, self->priv->allow_write);
			break;
		case ODS_SERVER_SESSION_AUTO_ACCEPT:
			g_value_set_boolean (value, self->priv->auto_accept);
			break;
		case ODS_SERVER_SESSION_REQUIRE_IMAGING_THUMBNAILS:
			g_value_set_boolean (value, self->priv->require_imaging_thumbnails);
			break;
		case ODS_SERVER_SESSION_USING_TTY:
			g_value_set_boolean (value, self->priv->using_tty);
			break;
		case ODS_SERVER_SESSION_OWNER:
			g_value_set_string (value, self->priv->owner);
			break;
		case ODS_SERVER_SESSION_DBUS_PATH:
			g_value_set_string (value, self->priv->dbus_path);
			break;
		default:
			/* We don't have any other property... */
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object,property_id,pspec);
			break;
	}
}

/**
 * ods_server_session_class_init:
 * @klass: The OdsServerSessionClass
 **/
static void
ods_server_session_class_init (OdsServerSessionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = ods_server_session_finalize;

	object_class->set_property = ods_server_session_set_property;
	object_class->get_property = ods_server_session_get_property;

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_SESSION_FD,
	                                 g_param_spec_int ("fd",
	                                                   "", "",
	                                                   -1, G_MAXINT, /* min, max values */
	                                                   0 /* default value */,
	                                                   G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_SESSION_SERVICE,
	                                 g_param_spec_int ("service",
	                                                   "", "",
	                                                   0, G_MAXINT, /* min, max values */
	                                                   0 /* default value */,
	                                                   G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_SESSION_PATH,
	                                 g_param_spec_string ("path",
	                                                      "", "",
	                                                      "" /* default value */,
	                                                      G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_SESSION_OWNER,
	                                 g_param_spec_string ("owner",
	                                                      "", "",
	                                                      "" /* default value */,
	                                                      G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_SESSION_ALLOW_WRITE,
	                                 g_param_spec_boolean("allow-write",
	                                                      "", "",
	                                                      FALSE,
	                                                      G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_SESSION_AUTO_ACCEPT,
	                                 g_param_spec_boolean("auto-accept",
	                                                      "", "",
	                                                      TRUE,
	                                                      G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_SESSION_REQUIRE_IMAGING_THUMBNAILS,
	                                 g_param_spec_boolean("require-imaging-thumbnails",
	                                                      "", "",
	                                                      FALSE,
	                                                      G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_SESSION_USING_TTY,
	                                 g_param_spec_boolean("using-tty",
	                                                      "", "",
	                                                      FALSE,
	                                                      G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_SESSION_DBUS_PATH,
	                                 g_param_spec_string ("dbus-path",
	                                                      "", "",
	                                                      "" /* default value */,
	                                                      G_PARAM_READABLE));

	signals [CANCELLED] =
	    g_signal_new ("cancelled",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerSessionClass, cancelled),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);
	signals [DISCONNECTED] =
	    g_signal_new ("disconnected",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerSessionClass, disconnected),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);
	signals [TRANSFER_STARTED] =
	    g_signal_new ("transfer-started",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerSessionClass, transfer_started),
	                  NULL,
	                  NULL,
	                  ods_marshal_VOID__STRING_STRING_UINT64,
	                  G_TYPE_NONE, 3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT64);
	signals [TRANSFER_PROGRESS] =
	    g_signal_new ("transfer-progress",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerSessionClass, transfer_progress),
	                  NULL,
	                  NULL,
	                  ods_marshal_VOID__UINT64,
	                  G_TYPE_NONE, 1, G_TYPE_UINT64);
	signals [TRANSFER_COMPLETED] =
	    g_signal_new ("transfer-completed",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerSessionClass, transfer_completed),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);
	signals [ERROR_OCCURRED] =
	    g_signal_new ("error-occurred",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerSessionClass, error_occurred),
	                  NULL,
	                  NULL,
	                  ods_marshal_VOID__STRING_STRING,
	                  G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);
	signals [REMOTE_DISPLAY_REQUESTED] =
	    g_signal_new ("remote-display-requested",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerSessionClass, remote_display_requested),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__STRING,
	                  G_TYPE_NONE, 1, G_TYPE_STRING);

	g_type_class_add_private (klass, sizeof (OdsServerSessionPrivate));

	GError *error = NULL;

	/* Init the DBus connection, per-klass */
	klass->connection = dbus_g_bus_get (ODS_DBUS_BUS, &error);
	if (klass->connection == NULL) {
		g_warning("Unable to connect to dbus: %s", error->message);
		g_clear_error (&error);
		return;
	}

	/* &dbus_glib_ods_server_session_object_info is provided in the
	 * dbus/ods-server-session-dbus-glue.h file */
	dbus_g_object_type_install_info (ODS_TYPE_SERVER_SESSION, &dbus_glib_ods_server_session_object_info);
}

/**
 * ods_server_session_init:
 * @server_session: This class instance
 **/
static void
ods_server_session_init (OdsServerSession *server_session)
{
	OdsServerSessionClass *klass = ODS_SERVER_SESSION_GET_CLASS (server_session);
	server_session->priv = ODS_SERVER_SESSION_GET_PRIVATE (server_session);

	server_session->priv->obex_context = ods_obex_context_new ();

	/* figure out DBus object path for this instance */
	server_session->priv->state = ODS_SERVER_SESSION_STATE_OPEN;
	server_session->priv->dbus_path = g_strdup_printf (ODS_SERVER_SESSION_DBUS_PATH_PATTERN,
	                                  iterator);
	iterator++;
	/* default selected image handle for BIP RemoteDisplay is 0000001 */
	server_session->priv->selected_img = 1;

	/* create mutex */
	g_static_mutex_init (&server_session->priv->mutex);

	dbus_g_connection_register_g_object (klass->connection,
	                                     server_session->priv->dbus_path,
	                                     G_OBJECT (server_session));
}

/**
 * ods_server_session_finalize:
 * @object: The object to finalize
 *
 * Finalize the session
 **/
static void
ods_server_session_finalize (GObject *object)
{
	OdsServerSession *server_session;

	g_return_if_fail (object != NULL);
	g_return_if_fail (ODS_IS_SERVER_SESSION (object));

	server_session = ODS_SERVER_SESSION (object);

	g_return_if_fail (server_session->priv != NULL);

	/* close connection, free obex_context */
	g_message ("closing connection");

	/* In TTY mode, fd ownership will revert to the OdsServer, so don't
	 * close it. See server_session_disconnected_cb. */
	if (!server_session->priv->using_tty) {
		shutdown (server_session->priv->fd, SHUT_RDWR);
		close (server_session->priv->fd);
	}
	server_session->priv->fd = -1;

	OBEX_Cleanup (server_session->priv->obex_context->obex_handle);
	g_free (server_session->priv->obex_context);

	/* free other private variables */
	if (server_session->priv->img_handle_list)
		g_hash_table_unref (server_session->priv->img_handle_list);
	g_free (server_session->priv->root_path);
	g_free (server_session->priv->path);
	g_free (server_session->priv->owner);
	g_free (server_session->priv->dbus_path);
	g_static_mutex_free (&server_session->priv->mutex);

	G_OBJECT_CLASS (ods_server_session_parent_class)->finalize (object);
}

/**
 * ods_server_session_new:
 *
 * Return value: a new OdsServerSession object.
 **/
OdsServerSession *
ods_server_session_new (gint fd, gint service, const gchar *path,
                        gboolean allow_write, gboolean auto_accept,
                        gboolean require_imaging_thumbnails,
                        const gchar *owner)
{
	OdsServerSession *server_session;
	server_session = g_object_new (ODS_TYPE_SERVER_SESSION,
	                               "fd", fd,
	                               "service", service,
	                               "path", path,
	                               "allow-write", allow_write,
	                               "auto-accept", auto_accept,
	                               "require-imaging-thumbnails", require_imaging_thumbnails,
	                               "owner", owner,
	                               NULL);
	return ODS_SERVER_SESSION (server_session);
}

gboolean
ods_server_session_accept (OdsServerSession *server_session,
                           DBusGMethodInvocation *context)
{
	GError	*error = NULL;

	ODS_SERVER_SESSION_LOCK (server_session);
	/* do checks */
	if (!ods_check_caller (context, server_session->priv->owner)) {
		ODS_SERVER_SESSION_UNLOCK (server_session);
		return FALSE;
	}
	if (server_session->priv->state != ODS_SERVER_SESSION_STATE_BUSY) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "There is no transfer in progress");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SERVER_SESSION_UNLOCK (server_session);
		return FALSE;
	}

	/* Accept file */
	server_session->priv->obex_context->suspend_result = OBEX_SUSP_ACCEPTED;

	dbus_g_method_return (context);
	ODS_SERVER_SESSION_UNLOCK (server_session);
	return TRUE;
}

gboolean
ods_server_session_reject (OdsServerSession *server_session,
                           DBusGMethodInvocation *context)
{
	GError	*error = NULL;

	ODS_SERVER_SESSION_LOCK (server_session);
	/* do checks */
	if (!ods_check_caller (context, server_session->priv->owner)) {
		ODS_SERVER_SESSION_UNLOCK (server_session);
		return FALSE;
	}
	if (server_session->priv->state != ODS_SERVER_SESSION_STATE_BUSY) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "There is no transfer in progress");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SERVER_SESSION_UNLOCK (server_session);
		return FALSE;
	}

	/* Reject file */
	server_session->priv->obex_context->suspend_result = OBEX_SUSP_REJECTED;

	dbus_g_method_return (context);
	ODS_SERVER_SESSION_UNLOCK (server_session);
	return TRUE;
}

void
ods_server_session_disconnect_internal (OdsServerSession *server_session)
{
	if (server_session->priv->state == ODS_SERVER_SESSION_STATE_OPEN) {
		OBEX_TransportDisconnect (server_session->priv->obex_context->obex_handle);
		server_session->priv->state = ODS_SERVER_SESSION_STATE_NOT_CONNECTED;
	}
	g_idle_add ((GSourceFunc) emit_disconnected, server_session);
}

gboolean
ods_server_session_disconnect (OdsServerSession *server_session,
                               DBusGMethodInvocation *context)
{
	GError	*error = NULL;

	ODS_SERVER_SESSION_LOCK (server_session);
	/* do checks */
	if (!ods_check_caller (context, server_session->priv->owner)) {
		ODS_SERVER_SESSION_UNLOCK (server_session);
		return FALSE;
	}
	if (server_session->priv->state == ODS_SERVER_SESSION_STATE_BUSY) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_BUSY,
		             "Operations in progress need to be cancelled first");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		ODS_SERVER_SESSION_UNLOCK (server_session);
		return FALSE;
	}

	ods_server_session_disconnect_internal (server_session);
	dbus_g_method_return (context);

	ODS_SERVER_SESSION_UNLOCK (server_session);
	return TRUE;
}

GHashTable *
ods_server_session_get_transfer_info (OdsServerSession *server_session)
{
	return ods_obex_transfer_get_info (server_session->priv->obex_context);
}

gboolean
ods_server_session_cancel_internal (OdsServerSession *server_session)
{
	OdsObexContext *ctxt = server_session->priv->obex_context;

	if (server_session->priv->state != ODS_SERVER_SESSION_STATE_BUSY) {
		/* emit CANCELLED signal now */
		g_signal_emit (server_session, signals[CANCELLED], 0);
		return FALSE;
	}

	if (ctxt->obex_cmd == OBEX_CMD_GET) {
		/* Send CMD_ABORT now */
		OBEX_CancelRequest (ctxt->obex_handle, TRUE);
	} else {
		/* Send RSP_FORBIDDEN at obex_readstream;
		 * cleanup will be done in obex_event */
		ctxt->cancelled = TRUE;
	}
	/* In case ServerSession got stuck in suspended mode (client app quitted without
	 * accepting/rejecting transfer), we reject transfer at this point */
	server_session->priv->obex_context->suspend_result = OBEX_SUSP_REJECTED;
	return TRUE;
}

gboolean
ods_server_session_cancel (OdsServerSession *server_session,
                           DBusGMethodInvocation *context)
{
	ODS_SERVER_SESSION_LOCK (server_session);
	/* do checks */
	if (!ods_check_caller (context, server_session->priv->owner)) {
		ODS_SERVER_SESSION_UNLOCK (server_session);
		return FALSE;
	}

	if (ods_server_session_cancel_internal (server_session)) {
		if (server_session->priv->dbus_context) {
			GError *error;

			g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
			             "DBus context is set (this is probably a bug)");
			dbus_g_method_return_error (context, error);
			g_clear_error (&error);
			ODS_SERVER_SESSION_UNLOCK (server_session);
			return FALSE;
		}
		/* set dbus context */
		server_session->priv->dbus_context = context;
		/* will return at obex_event{EV_ABORT} */
	} else {
		dbus_g_method_return (context);
		ODS_SERVER_SESSION_UNLOCK (server_session);
	}

	return TRUE;
}

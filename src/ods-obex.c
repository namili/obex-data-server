/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*-
 *
 * Copyright (C) 2007-2009 Tadas Dailyda <tadas@dailyda.com>
 * Parts of code taken from osso-gwobex library by:
 * 				Johan Hedberg <johan.hedberg@nokia.com>
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

#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <bluetooth/sdp.h>
#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "ods-capabilities.h"
#include "ods-common.h"
#include "ods-folder-listing.h"
#include "ods-imaging-helpers.h"
#include "ods-obex.h"
#include "ods-session.h"
#include "ods-error.h"

#define ATTACHMENT_FILENAME "attachment"


static void
get_target_size_and_time (obex_t *handle, obex_object_t *object,
                          guint64 *size, time_t *time)
{
	obex_headerdata_t hv;
	uint8_t hi;
	unsigned int hlen;

	*size = 0;
	*time = -1;

	while (OBEX_ObjectGetNextHeader(handle, object, &hi, &hv, &hlen)) {
		switch (hi) {
			case OBEX_HDR_LENGTH:
				*size = hv.bq4;
				break;
			case OBEX_HDR_TIME:
				*time = ods_parse_iso8601 ((char *)hv.bs, hlen);
				break;
			default:
				break;
		}
	}

	OBEX_ObjectReParseHeaders (handle, object);
}

/**
 * ods_process_usb_input:
 * @data: obex_t handle
 *
 * Idle callback that reads data from a USB interface
 *
 * Return value: whether there is more data to read
 **/
static gboolean
ods_process_usb_input (gpointer data)
{
	OdsObexContext	*ctxt = (OdsObexContext *) data;

	int i = OBEX_HandleInput (ctxt->obex_handle, 1);
	if (i <= 0) {
		/* Link error: for example USB cable was disconnected */
		(ctxt->io_callback) (NULL, G_IO_ERR, ctxt->obex_handle);
		return FALSE;
	}

	return ctxt->usb_read_more;
}

static gboolean
ods_obex_timeout (gpointer data)
{
	OdsObexContext *ctxt = (OdsObexContext *) data;
	obex_object_t *object;

	g_message ("Request timeout (%ds), session considered dead", ODS_OBEX_TIMEOUT);
	ctxt->timeout_id = 0;
	/* issue dummy obex_event with OBEX_RSP_REQUEST_TIME_OUT */
	if (ctxt->obex_event) {
		object = OBEX_ObjectNew(ctxt->obex_handle, ctxt->obex_cmd);
		(ctxt->obex_event) (ctxt->obex_handle, object, 0,
							OBEX_EV_REQDONE, ctxt->obex_cmd,
							OBEX_RSP_REQUEST_TIME_OUT);
		OBEX_ObjectDelete (ctxt->obex_handle, object);
	}

	/* issue dummy io_callback with G_IO_ERR condition
	 * (so that session gets disconnected) 
	 * also check that io_callback is not null (in some cases obex_context
	 * might have been already closed (ods_obex_close_transport() was called), 
	 * e.g. when CMD_CONNECT times out) */
	if (ctxt->io_callback) {
		(ctxt->io_callback) (NULL, G_IO_ERR, ctxt->obex_handle);
	}
	/* immediately remove io watch, we consider this connection dead */
	ods_safe_gsource_remove (&(ctxt->io_watch));

	return FALSE;
}

static gint
ods_obex_send (OdsObexContext *ctxt, obex_object_t *object)
{
	int err;
	OdsSession* session;
	gint usbintfnum;

	ctxt->obex_cmd = OBEX_ObjectGetCommand (ctxt->obex_handle, object);
	err = OBEX_Request (ctxt->obex_handle, object);

	if (err == -EBUSY) {
		g_warning ("EBUSY in ods_session_obex_send");
	}
	if (err >=0 ) {
		session = ODS_SESSION (OBEX_GetUserData (ctxt->obex_handle));
		g_object_get (session, "usbintfnum", &usbintfnum, NULL);

		if (usbintfnum >= 0) {
			/* It is not possible to use io_watch with USB,
			 * so data is read in a custom idle callback function */
			g_idle_add ((GSourceFunc)ods_process_usb_input, ctxt);
		}

		ctxt->timeout_id = g_timeout_add_seconds (ODS_OBEX_TIMEOUT,
		                   ods_obex_timeout, ctxt);
	}

	return err;
}

static gboolean
ods_obex_io (GIOChannel *io_channel, GIOCondition cond, gpointer data)
{
	OdsObexContext *ctxt = (OdsObexContext *) data;

	/* got data or error so cancel request timeout (if set) */
	ods_safe_gsource_remove (&(ctxt->timeout_id));
	/* call real io_callback */
	return (ctxt->io_callback) (io_channel, cond, ctxt->obex_handle);
}

static gchar *
ods_obex_get_new_path (const gchar *folder, const gchar *filename)
{
	gchar *path;
	gchar *new_path;
	guint iterator = 2;
	gchar *first_part;
	gchar *extension;
	gchar *parentess;
	guint pos;

	/* In case we don't know what the filename is (HDR_NAME wasn't received) */
	if (filename == NULL || *filename == '\0')
		filename = "Unknown";

	path = g_build_filename (folder, filename, NULL);
	new_path = g_strdup (path);

	extension = g_strrstr (path, ".");
	if (!extension)
		extension = "";
	while (g_file_test (new_path, G_FILE_TEST_EXISTS)) {
		if (iterator == 2) {
			parentess = g_strrstr (new_path, "(");
			if (parentess != NULL && !g_str_has_prefix (parentess, "(2)"))
				parentess = NULL;
			pos = parentess ? strlen (parentess) : strlen (extension);
			pos = strlen (new_path) - pos;
		} else {
			parentess = g_strrstr (new_path, "(");
			pos = strlen (new_path) - strlen (parentess);
		}
		first_part = g_strndup (new_path, pos);
		g_free (new_path);
		new_path = g_strdup_printf ("%s(%d)%s", first_part, iterator, extension);
		g_free (first_part);
		iterator++;
	}

	g_free (path);
	return new_path;
}

void
ods_obex_transfer_new (OdsObexContext *obex_context, const gchar *local,
                       const gchar *remote, const gchar *type)
{
	obex_context->local = g_strdup (local);
	obex_context->remote = g_strdup (remote);
	obex_context->type = g_strdup (type);
	obex_context->target_size = 0;
	obex_context->modtime = -1;
	obex_context->report_progress = TRUE; /* by default */
	obex_context->transfer_started_signal_emitted = FALSE;
	obex_context->cancelled = FALSE;
	obex_context->suspend_result = 0;
	obex_context->buf_size = 0;
	obex_context->buf = NULL;
	obex_context->stream_fd = -1;
	obex_context->counter = 0;
}

static gboolean
ods_obex_susp_timeout (gpointer data)
{
	OdsObexContext *ctxt = (OdsObexContext *) data;

	g_message ("Suspend timeout (%ds), rejecting incoming file", ODS_OBEX_TIMEOUT);
	ctxt->suspend_timeout_id = 0;
	ctxt->suspend_result = OBEX_SUSP_REJECTED;

	return FALSE;
}

void
ods_obex_transfer_suspend (OdsObexContext *ctxt)
{
	g_message ("Suspending request");
	ctxt->suspend_timeout_id = g_timeout_add_seconds (ODS_OBEX_TIMEOUT,
		                                              ods_obex_susp_timeout, ctxt);
	while (!ctxt->suspend_result)
		g_main_context_iteration (NULL, TRUE);
	ods_safe_gsource_remove (&(ctxt->suspend_timeout_id));
	g_message ("Suspend result: %d", ctxt->suspend_result);
}

void
ods_obex_transfer_close (OdsObexContext *obex_context)
{
	if (obex_context->local) {
		g_free (obex_context->local);
		obex_context->local = NULL;
	}
	if (obex_context->remote) {
		g_free (obex_context->remote);
		obex_context->remote = NULL;
	}
	if (obex_context->type) {
		g_free (obex_context->type);
		obex_context->type = NULL;
	}
	if (obex_context->img_handle) {
		g_free (obex_context->img_handle);
		obex_context->img_handle = NULL;
	}
	if (obex_context->ext_info) {
		g_hash_table_unref (obex_context->ext_info);
		obex_context->ext_info = NULL;
	}
	if (obex_context->buf) {
		g_free (obex_context->buf);
		obex_context->buf = NULL;
	}
	if (obex_context->fifo_watch > 0) {
		g_source_remove (obex_context->fifo_watch);
		obex_context->fifo_watch = 0;
	}
	if (obex_context->stream_fd >= 0)
		close (obex_context->stream_fd);
}

void
ods_obex_transfer_add_info (OdsObexContext *obex_context, gchar *key,
                            gchar *value)
{
	if (!key || !value)
		return;
	if (!obex_context->ext_info) {
		obex_context->ext_info = g_hash_table_new_full (g_str_hash,
		                         g_str_equal, NULL, g_free);
	}
	g_hash_table_insert (obex_context->ext_info, key, value);
}

GHashTable*
ods_obex_transfer_get_info (OdsObexContext *obex_context)
{
	GHashTable		*info;
	gchar			*time_str;
	GHashTableIter	iter;
	gpointer		key, value;

	info = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_free);
	g_hash_table_insert (info, "LocalPath", g_strdup (obex_context->local));
	g_hash_table_insert (info, "RemoteFilename", g_strdup (obex_context->remote));
	g_hash_table_insert (info, "Size",
	                     g_strdup_printf ("%" G_GUINT64_FORMAT,
	                                      obex_context->target_size));
	if (obex_context->type)
		g_hash_table_insert (info, "Type", g_strdup (obex_context->type));
	if (obex_context->modtime != -1) {
		time_str = (gchar *)g_malloc (17);
		ods_make_iso8601 (obex_context->modtime, time_str, sizeof (time_str));
		g_hash_table_insert (info, "Time", time_str);
	}
	if (obex_context->obex_cmd == OBEX_CMD_GET)
		g_hash_table_insert (info, "OBEXCommand", g_strdup ("GET"));
	else if (obex_context->obex_cmd == OBEX_CMD_PUT)
		g_hash_table_insert (info, "OBEXCommand", g_strdup ("PUT"));
	if (obex_context->img_handle)
		g_hash_table_insert (info, "ImageHandle",
		                     g_strdup (obex_context->img_handle));
	/* Add additional transfer info (if any) */
	if (obex_context->ext_info) {
		g_hash_table_iter_init (&iter, obex_context->ext_info);
		while (g_hash_table_iter_next (&iter, &key, &value))
			g_hash_table_insert (info, key, g_strdup (value));
	}
	return info;
}

OdsObexContext*
ods_obex_context_new (void)
{
	OdsObexContext *obex_context = g_new0 (OdsObexContext, 1);
	obex_context->rx_max = ODS_DEFAULT_RX_MTU;
	obex_context->tx_max = ODS_DEFAULT_TX_MTU - 200;
	obex_context->connection_id = CONID_INVALID;
	obex_context->stream_fd = -1;
	obex_context->protocol = RFCOMM_OBEX;
	return obex_context;
}

gboolean
ods_obex_setup_fdtransport (OdsObexContext *obex_context, gint fd,
                            guint16 rx_mtu, guint16 tx_mtu,
                            obex_event_t eventcb, GIOFunc io_cb,
                            gpointer user_data, GError **error)
{
	GIOChannel *chan;
	gint ret;

	/* call OBEX_Init, setup FD Transport here */
	obex_context->obex_event = eventcb;
	obex_context->io_callback = io_cb;
	obex_context->obex_handle = OBEX_Init (OBEX_TRANS_FD, eventcb, 0);
	if (obex_context->obex_handle == NULL) {
		g_set_error (error, ODS_ERROR, ODS_ERROR_FAILED, "Out of memory");
		return FALSE;
	}
	OBEX_SetUserData (obex_context->obex_handle, user_data);

	OBEX_SetTransportMTU (obex_context->obex_handle, rx_mtu, tx_mtu);
	g_message ("Used MTUs: RX=%u, TX=%u", rx_mtu, tx_mtu);

	if(obex_context->protocol==L2CAP_OBEX){
		ret = FdOBEX_TransportSetup (obex_context->obex_handle, fd, fd, 0,OBEX_MT_SEQPACKET);
		g_message ("data format is %d",OBEX_MT_SEQPACKET);
	}
	else{
		ret = FdOBEX_TransportSetup (obex_context->obex_handle, fd,	fd,	0,OBEX_MT_STREAM);
		g_message ("data format is %d",OBEX_MT_STREAM);
	}

	if (ret < 0) {
		OBEX_Cleanup (obex_context->obex_handle);
		g_set_error (error, ODS_ERROR, ODS_ERROR_FAILED, "Transport setup failed");
		return FALSE;
	}

	chan = g_io_channel_unix_new (fd);
	obex_context->io_watch = g_io_add_watch(chan,
	                                        G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
	                                        ods_obex_io, obex_context);
	g_io_channel_unref(chan);

	return obex_context->io_watch ? TRUE : FALSE;
}

gboolean
ods_obex_setup_usbtransport (OdsObexContext *obex_context, gint intf_num,
                             obex_event_t eventcb, GIOFunc io_cb,
                             gpointer user_data, GError **error)
{
	gint ret;
	obex_interface_t *obex_intf;
	int interfaces_num;

	/* call OBEX_Init, setup USB Transport here */
	obex_context->obex_event = eventcb;
	obex_context->io_callback = io_cb;
	obex_context->obex_handle = OBEX_Init (OBEX_TRANS_USB, eventcb, 0);
	if (obex_context->obex_handle == NULL) {
		g_set_error (error, ODS_ERROR, ODS_ERROR_FAILED, "Out of memory");
		goto err;
	}
#if 0
	interfaces_num = OBEX_FindInterfaces(obex_context->obex_handle, &obex_intf);
	if (intf_num >= interfaces_num) {
		g_set_error (error, ODS_ERROR, ODS_ERROR_FAILED, "Invalid interface number");
		goto err;
	}
#else
	
	interfaces_num = OBEX_EnumerateInterfaces(obex_context->obex_handle);
	if (intf_num >= interfaces_num) {
		g_set_error (error, ODS_ERROR, ODS_ERROR_FAILED, "Invalid interface number");
		goto err;
	}
	obex_intf = OBEX_GetInterfaceByIndex(obex_context->obex_handle, intf_num);	
#endif
	OBEX_SetUserData (obex_context->obex_handle, user_data);
	ret = OBEX_InterfaceConnect(obex_context->obex_handle, obex_intf);
	if (ret < 0) {
		g_set_error (error, ODS_ERROR, ODS_ERROR_FAILED, "USB setup failed");
		goto err;
	}

	return TRUE;

err:
	if (obex_context->obex_handle)
		OBEX_Cleanup (obex_context->obex_handle);
	return FALSE;
}

void
ods_obex_close_transport (OdsObexContext *ctxt)
{
	ods_safe_gsource_remove (&(ctxt->timeout_id));
	ods_safe_gsource_remove (&(ctxt->io_watch));
	ctxt->obex_event = NULL;
	ctxt->io_callback = NULL;
}

gchar *
ods_obex_get_buffer_as_string (OdsObexContext *obex_context)
{
	/* put /0 in the end */
	obex_context->buf = g_realloc (obex_context->buf, obex_context->buf_size+1);
	obex_context->buf[obex_context->buf_size] = 0;
	return (gchar *)obex_context->buf;
}

gboolean
ods_obex_srv_new_file (OdsObexContext *obex_context, const gchar *path)
{
	/* Get local path */
	obex_context->local = ods_obex_get_new_path (path, obex_context->remote);
	/* open local file for writing */
	obex_context->stream_fd = open (obex_context->local, O_WRONLY | O_CREAT, 0666);

	return obex_context->stream_fd >= 0;
}

gint
ods_obex_connect_done (OdsObexContext *obex_context,
                       obex_object_t *object)
{
	obex_headerdata_t hv;
	uint8_t hi;
	unsigned int hlen;
	uint8_t *ptr;

	if (OBEX_ObjectGetNonHdrData (object, &ptr)
	        != sizeof (obex_connect_hdr_t)) {
		return -1;
	} else {
		obex_connect_hdr_t *nonhdrdata = (obex_connect_hdr_t *) ptr;
		uint16_t mtu = g_ntohs( nonhdrdata->mtu);
		int new_size;
		g_message ("Version: 0x%02x. Flags: 0x%02x  OBEX packet length: %d",
		           nonhdrdata->version, nonhdrdata->flags, mtu);
		/* Leave space for headers */
		new_size = mtu - 200;
		if (new_size < obex_context->tx_max) {
			g_message ("Resizing stream chunks to %d", new_size);
			obex_context->tx_max = new_size;
		}
	}
	/* parse headers */
	while (OBEX_ObjectGetNextHeader(obex_context->obex_handle, object,
	                                &hi, &hv, &hlen)) {
		switch (hi) {
			case OBEX_HDR_CONNECTION:
				obex_context->connection_id = hv.bq4;
				break;
			default:
				break;
		}
	}

	return 0;
}

gint
ods_obex_connect (OdsObexContext *obex_context, const guchar *uuid,
                  guint uuid_length)
{
	obex_object_t *object;
	obex_headerdata_t hd;
	int ret;

	object = OBEX_ObjectNew(obex_context->obex_handle, OBEX_CMD_CONNECT);
	if (!object) {
		return -ENOMEM;
	}

	/* Add target header */
	if (uuid) {
		hd.bs = uuid;

		ret = OBEX_ObjectAddHeader(obex_context->obex_handle, object,
		                           OBEX_HDR_TARGET, hd, uuid_length,
		                           OBEX_FL_FIT_ONE_PACKET);
		if (ret < 0) {
			OBEX_ObjectDelete(obex_context->obex_handle, object);
			return ret;
		}
	}

	ret = ods_obex_send(obex_context, object);
	if (ret < 0)
		OBEX_ObjectDelete(obex_context->obex_handle, object);

	return ret;
}

gint
ods_obex_srv_connect (OdsObexContext *obex_context, obex_object_t *object,
                      guint service)
{
	obex_headerdata_t	hv;
	uint8_t				hi;
	guint				hlen;
	uint8_t				*ptr;
	const guchar		*target = NULL;
	guint				target_len = 0;
	obex_headerdata_t	hd;
	gint				ret;

	if (OBEX_ObjectGetNonHdrData (object, &ptr)
	        != sizeof (obex_connect_hdr_t)) {
		return -1;
	} else {
		obex_connect_hdr_t *nonhdrdata = (obex_connect_hdr_t *) ptr;
		uint16_t mtu = g_ntohs (nonhdrdata->mtu);
		int new_size;
		g_message ("Version: 0x%02x. Flags: 0x%02x  OBEX packet length: %d",
		           nonhdrdata->version, nonhdrdata->flags, mtu);
		/* Leave space for headers */
		new_size = mtu - 200;
		if (new_size < obex_context->tx_max) {
			g_message ("Resizing stream chunks to %d", new_size);
			obex_context->tx_max = new_size;
		}
	}
	/* parse headers */
	while (OBEX_ObjectGetNextHeader(obex_context->obex_handle, object,
	                                &hi, &hv, &hlen)) {
		if (hi == OBEX_HDR_TARGET) {
			target = hv.bs;
			target_len = hlen;
		}
	}

	OBEX_ObjectReParseHeaders (obex_context->obex_handle, object);

	switch (service) {
		case ODS_SERVICE_FTP:
			/* Target header must be F9EC7BC4-953C-11D2-984E-525400DC9E09*/
			if (!target || memcmp(OBEX_FTP_UUID, target, hlen) != 0) {
				g_message("Target header Incorrect");
				goto fail;
			}
			break;
		case ODS_SERVICE_PBAP:
			/* Target header must be 796135f0-f0c5-11d8-0966-0800200c9a66 */
			if (!target || memcmp(OBEX_PBAP_UUID, target, hlen) != 0) {
				g_message("Target header Incorrect");
				goto fail;
			}
			break;
		case ODS_SERVICE_BIP:
			if (!target) {
				g_message("No Target header received for BIP connection");
				goto fail;
			}
			if (!memcmp (OBEX_BIP_IPUSH_UUID, target, hlen))
				break;
			if (!memcmp (OBEX_BIP_RD_UUID, target, hlen))
				break;
			g_message ("Unsupported Imaging feature requested");
			goto fail;
		case ODS_SERVICE_OPP:
			/* Target header must not be used */
			if (target) {
				g_message("Target header must not be used");
				goto fail;
			}
			OBEX_ObjectSetRsp (object, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);

			return 0;
		default:
			goto fail;
	}

	hd.bs = target;
	ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
	                            OBEX_HDR_WHO, hd, target_len,
	                            OBEX_FL_FIT_ONE_PACKET);
	if (ret < 0) {
		OBEX_ObjectDelete (obex_context->obex_handle, object);
		return ret;
	}

	hd.bs = NULL;
	hd.bq4 = 1; /* Connection ID is always 1 */
	obex_context->connection_id = 1;
	ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
	                            OBEX_HDR_CONNECTION, hd, 4,
	                            OBEX_FL_FIT_ONE_PACKET);
	if (ret < 0) {
		OBEX_ObjectDelete (obex_context->obex_handle, object);
		return ret;
	}

	OBEX_ObjectSetRsp (object, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);

	return 0;

fail:

	OBEX_ObjectSetRsp (object, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);

	return 0;
}

gint
ods_obex_disconnect (OdsObexContext *obex_context)
{
	obex_object_t	*object;
	gint			ret;

	g_message ("Sending CMD_DISCONNECT");
	object = OBEX_ObjectNew(obex_context->obex_handle, OBEX_CMD_DISCONNECT);
	if (!object) {
		return -ENOMEM;
	}

	/* Add connection header */
	if (obex_context->connection_id != CONID_INVALID) {
		obex_headerdata_t hv;
		hv.bq4 = obex_context->connection_id;
		ret = OBEX_ObjectAddHeader(obex_context->obex_handle, object,
		                           OBEX_HDR_CONNECTION, hv, 4, 0);
		if (ret < 0) {
			OBEX_ObjectDelete(obex_context->obex_handle, object);
			return ret;
		}
	}

	ret = ods_obex_send (obex_context, object);
	if (ret < 0)
		OBEX_ObjectDelete(obex_context->obex_handle, object);

	return ret;
}

static gboolean
fifo_watch (GIOChannel *io_channel, GIOCondition cond, gpointer data)
{
	OdsObexContext *obex_context = (OdsObexContext*) data;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		obex_context->suspend_result = OBEX_SUSP_FIFO_ERR;
		return FALSE;
	}
	obex_context->suspend_result = OBEX_SUSP_FIFO_ACT;
	return TRUE;
}

gint
ods_obex_readstream (OdsObexContext *obex_context, obex_object_t *object)
{
	const uint8_t	*buf;
	gint			actual;
	gint			written = 0;
	gint			write_ret;
	gint			ret = 0;

	if (obex_context->target_size == 0 && obex_context->counter == 0) {
		/* first data came in, get size and time */
		get_target_size_and_time (obex_context->obex_handle, object,
		                          &obex_context->target_size,
		                          &obex_context->modtime);
	}

	if (obex_context->cancelled) {
		/* It's not possible to cancel incoming request by sending CMD_ABORT
		 * hence we set RSP_FORBIDDEN response */
		 //OBEX_ObjectSetRsp (object, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		ret = 2;
		goto out;
	}

	actual = OBEX_ObjectReadStream (obex_context->obex_handle, object, &buf);
	if (actual >= 0) {
		g_message ("There is some data");
		obex_context->counter += actual;

		if (obex_context->stream_fd >= 0) {
			/* write data to file */
			while (written < actual) {
				write_ret = write (obex_context->stream_fd, buf + written,
				                   actual - written);
				written += write_ret;

				if (write_ret < 0) {
					if (errno == EINTR)
						continue;
					else if (errno == EAGAIN) {
						/* FIFO is full, wait for it to be read */
						ods_obex_transfer_suspend (obex_context);
						if (obex_context->suspend_result == OBEX_SUSP_FIFO_ACT) {
							obex_context->suspend_result = 0;
							/* FIFO was read, we can continue writing */
							continue;
						} else {
							obex_context->suspend_result = 0;
							/* FIFO error, cancel transfer */
							OBEX_ObjectSetRsp (object, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
							ret = 2;
							goto out;
						}
					} else {
						ret = -errno;
						goto out;
					}
				}
			}
		} else {
			g_message ("Writing to buf");
			/* write data to internal buffer */
			obex_context->buf = g_realloc (obex_context->buf,
			                               obex_context->counter);
			memcpy (&obex_context->buf[obex_context->buf_size], buf, actual);
			obex_context->buf_size = obex_context->counter;
		}
	} else {
		/* No data on OBEX stream */
		ret = 1;
	}

out:
	if (ret < 0) {
		/* close this transfer */
		ods_obex_transfer_close (obex_context);
	}

	return ret;
}

gint
ods_obex_writestream (OdsObexContext *obex_context, obex_object_t *object)
{
	g_message ("obex_writestream");
	obex_headerdata_t	hv;
	gint				actual = -1;
	gint				read_bytes = 0;
	gint				ret = 0;

	if (obex_context->cancelled) {
		ret = -1;
		goto out;
	}
	if (obex_context->stream_fd >= 0) {
		g_message ("writestream from File: %d", obex_context->stream_fd);
		hv.bs = obex_context->buf;
		while (read_bytes < obex_context->tx_max) {
			actual = read (obex_context->stream_fd, obex_context->buf+read_bytes,
			               obex_context->tx_max-read_bytes);
			read_bytes += actual;
			if (actual > 0) {
				obex_context->counter += actual;
				if (read_bytes < obex_context->tx_max) {
					if (obex_context->fifo_watch > 0) {
						g_message ("FIFO (read less than needed), waiting for data");
fifo_suspend:
						ods_obex_transfer_suspend (obex_context);
						if (obex_context->suspend_result == OBEX_SUSP_FIFO_ACT) {
							obex_context->suspend_result = 0;
							/* FIFO has more data, we can read */
							g_message ("FIFO (continue reading)");
							continue;
						} else {
							obex_context->suspend_result = 0;
							/* FIFO error, cancel transfer */
							g_message ("FIFO (reading failed)");
							OBEX_CancelRequest (obex_context->obex_handle, TRUE);
							ret = 2;
							goto out;
						}
					} else
						break;
				}
			} else if (actual == 0 && read_bytes == 0) {
				g_message ("read 0 bytes (EOF)");
				/* EOF */
				OBEX_ObjectAddHeader (obex_context->obex_handle, object,
				                      OBEX_HDR_BODY, hv, 0,
				                      OBEX_FL_STREAM_DATAEND);
				/* transfer done */
				ret = 1;
				goto out;
			} else {
				if (obex_context->fifo_watch > 0 && errno == EAGAIN)
					goto fifo_suspend;
				else {
					g_message ("read error %s", strerror (errno));
					/* error reading file */
					ret = -errno;
					goto out;
				}
			}
		}
		if (read_bytes > 0) {
			OBEX_ObjectAddHeader (obex_context->obex_handle, object,
			                      OBEX_HDR_BODY, hv, read_bytes,
			                      OBEX_FL_STREAM_DATA);
			/* Everything OK, continue sending data */
			ret = 0;
		}
	} else if (obex_context->buf_size > 0) {
		g_message ("writestream from Buffer");
		/* used only in server mode to send folder listings and such */
		actual = obex_context->buf_size - obex_context->counter;
		if (actual > obex_context->tx_max)
			actual = obex_context->tx_max;
		g_message ("buf_size: %" G_GUINT64_FORMAT ", actual: %d",
		           obex_context->buf_size, actual);
		hv.bs = &obex_context->buf[obex_context->counter];
		if (actual > 0) {
			OBEX_ObjectAddHeader (obex_context->obex_handle, object,
			                      OBEX_HDR_BODY, hv, actual,
			                      OBEX_FL_STREAM_DATA);
			obex_context->counter += actual;
			/* Everything OK, continue sending data */
			ret = 0;
		} else if (actual == 0) {
			/* EOF */
			OBEX_ObjectAddHeader (obex_context->obex_handle, object,
			                      OBEX_HDR_BODY, hv, 0,
			                      OBEX_FL_STREAM_DATAEND);
			/* transfer done */
			ret = 1;
		}
	} else {
		/* shouldn't happen */
		g_warning ("Invalid fd while transfer in progress");
		ret = -1;
	}

out:
	if (ret < 0) {
		/* close this transfer */
		ods_obex_transfer_close (obex_context);
	}

	return ret;
}

gint
ods_obex_get (OdsObexContext *obex_context,
              const gchar *local, const gchar *remote,
              const gchar *type, gboolean is_fifo)
{
	gint				ret;
	obex_headerdata_t	hv;
	obex_object_t		*object;
	gchar				*uname;
	gsize				uname_len = 0;

	g_assert (remote || type);

	ods_obex_transfer_new (obex_context, local, remote, type);

	object = OBEX_ObjectNew (obex_context->obex_handle, OBEX_CMD_GET);
	if (!object) {
		ret = -ENOMEM;
		goto out;
	}

	/* Add connection header */
	if (obex_context->connection_id != CONID_INVALID) {
		hv.bq4 = obex_context->connection_id;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_CONNECTION, hv, 4, 0);
		if (ret < 0)
			goto out;
	}

	/* Add type header */
	if (type) {
		hv.bs = (guchar *)type;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_TYPE, hv, strlen (type) + 1, 0);
		if (ret < 0)
			goto out;
	}

	/* Add name header */
	if (remote) {


		uname_len = ods_filename_to_utf16 (&uname, remote);
		if (uname == NULL) {
			ret = -EINVAL;
			goto out;
		}

		/* OpenOBEX is buggy and won't append the header unless hv.bs != NULL */
		hv.bs = (guchar *) uname;

		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_NAME, hv, uname_len, 0);
		if (ret < 0)
			goto out;
		
		if(obex_context->protocol==L2CAP_OBEX){
			/*Add SRM header*/
			hv.bq1 = OBEX_SRM_ENABLE;
			ret = OBEX_ObjectAddHeader(obex_context->obex_handle, object,
					OBEX_HDR_SRM, hv, 1,
					0);
			
			if (ret < 0)
				goto out;
		}
	}

	/* Add local name header */
	if (local) {
		int oflags;

		if (is_fifo)
			oflags = O_WRONLY | O_NONBLOCK;
		else
			oflags = O_WRONLY | O_CREAT;
		obex_context->stream_fd = open (local, oflags, 0666);
		if (obex_context->stream_fd < 0) {
			ret = -errno;
			goto out;
		}
		if (is_fifo) {
			GIOChannel *chan;

			/* Setup IO watch to know when it is possible to write to FIFO or error happens */
			chan = g_io_channel_unix_new (obex_context->stream_fd);
			obex_context->fifo_watch = g_io_add_watch (chan,
			                           G_IO_OUT | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			                           fifo_watch, obex_context);
			g_io_channel_unref (chan);
		}
	} else {
		/* don't report progress when receiving to internal buffer only */
		obex_context->report_progress = FALSE;
	}
	/* Initiate transfer */
	OBEX_ObjectReadStream (obex_context->obex_handle, object, NULL);
	ret = ods_obex_send (obex_context, object);
out:
	if (uname_len > 0)
		g_free (uname);
	if (ret < 0 && object)
		OBEX_ObjectDelete (obex_context->obex_handle, object);
	if (ret < 0 && obex_context->stream_fd >= 0)
		g_unlink (obex_context->local); /* delete incomplete file */
	if (ret < 0)
		ods_obex_transfer_close (obex_context);
	return ret;
}

gint
ods_obex_srv_get (OdsObexContext *obex_context, obex_object_t *object,
                  const gchar *current_path, const gchar *root_path,
                  gboolean allow_write)
{
	obex_headerdata_t	hv;
	uint8_t				hi;
	guint				hlen;
	gint				object_size = 0;
	time_t				object_time = -1;
	gint				ret;

	g_message ("stream_fd=%d", obex_context->stream_fd);
	while (OBEX_ObjectGetNextHeader (obex_context->obex_handle, object,
	                                 &hi, &hv, &hlen)) {
		switch (hi) {
			case OBEX_HDR_NAME:
				if (hlen == 0) {
					/* This is GET by Type, leave remote = NULL */
					break;
				}
				obex_context->remote = ods_filename_from_utf16 ((gchar *) hv.bs, hlen);
				break;

			case OBEX_HDR_TYPE:
				if (hv.bs[hlen - 1] != '\0' ||
				        !g_utf8_validate ((const gchar *) hv.bs, -1, NULL)) {
					/* invalid type header */
					g_message ("HDR_TYPE invalid: %s", (gchar*) hv.bs);
				}
				else {
					obex_context->type = g_strdup ((const gchar *) hv.bs);
					g_message ("HDR_TYPE: %s", obex_context->type);
				}
				break;

			case OBEX_HDR_CONNECTION:
				if (obex_context->connection_id != CONID_INVALID &&
				        hv.bq4 != obex_context->connection_id) {
					/* wrong connection id */
					ret = -1;
					OBEX_ObjectSetRsp (object, OBEX_RSP_BAD_REQUEST, OBEX_RSP_BAD_REQUEST);
					goto out;
				}
				break;
				
			case OBEX_HDR_SRM:
				if(obex_context->protocol==RFCOMM_OBEX)
					break;
				if (hv.bq1 == OBEX_SRM_ENABLE) {
					hv.bq1 = OBEX_SRM_ENABLE;
					OBEX_ObjectAddHeader(obex_context->obex_handle, object,
							OBEX_HDR_SRM, hv, 1,
							OBEX_FL_FIT_ONE_PACKET);
					OBEX_SetEnableSRM(object);
					g_message("ods_obex_srv_get Enable srm");
				} 
				else if (hv.bq1 == OBEX_SRM_ADVERTISE) {
					hv.bq1 = OBEX_SRM_ENABLE;
					OBEX_ObjectAddHeader(obex_context->obex_handle, object,
							OBEX_HDR_SRM, hv, 1,
							OBEX_FL_FIT_ONE_PACKET);				
				}
				break;			
			default:
				break;
		}
	}
	
	if (obex_context->remote)
		g_message ("name: %s", obex_context->remote);
	if (obex_context->type)
		g_message ("type: %s", obex_context->type);
	if (obex_context->remote &&((obex_context->type==NULL)||strcmp (obex_context->type, LST_TYPE))) {
		/* If we have name header but type is NOT x-obex/folder-listing */
		obex_context->local = g_build_filename (current_path,
		                                        obex_context->remote,
		                                        NULL);
		g_message ("local filename: %s", obex_context->local);
		/* Check if such file exists */
		if (!g_file_test (obex_context->local, G_FILE_TEST_EXISTS)) {
			ret = -1;
			OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_FOUND, OBEX_RSP_NOT_FOUND);
			goto out;
		}
		if (!g_file_test (obex_context->local, G_FILE_TEST_IS_REGULAR)) {
			ret = -1;
			OBEX_ObjectSetRsp (object, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
			goto out;
		}
		if (g_access (obex_context->local, R_OK) < 0) {
			ret = -1;
			OBEX_ObjectSetRsp (object, OBEX_RSP_UNAUTHORIZED, OBEX_RSP_UNAUTHORIZED);
			goto out;
		}
	}
	if (obex_context->remote)
		g_message ("name: %s", obex_context->remote);
	if (obex_context->type)
		g_message ("type: %s", obex_context->type);

	OBEX_ObjectReParseHeaders (obex_context->obex_handle, object);

	if (obex_context->local) {
		g_message ("Serving local file");
		/* open local file for reading */
		obex_context->stream_fd = open (obex_context->local, O_RDONLY);
		if (obex_context->stream_fd < 0) {
			ret = -1;
			OBEX_ObjectSetRsp (object, OBEX_RSP_INTERNAL_SERVER_ERROR, OBEX_RSP_INTERNAL_SERVER_ERROR);
			goto out;
		}
		/* allocate buffer */
		obex_context->buf = g_malloc (obex_context->tx_max);
		obex_context->buf_size = obex_context->tx_max;

		/* Try to figure out modification time and size */
		struct stat stats;
		if (fstat (obex_context->stream_fd, &stats) == 0) {
			object_size = stats.st_size;
			object_time = stats.st_mtime;
			obex_context->modtime = object_time;
		}

		/* Add a time header */
		if (object_time >= 0) {
			gchar tstr[17];
			gint len;

			len = ods_make_iso8601 (object_time, tstr, sizeof (tstr));

			if (len >= 0) {
				hv.bs = (guchar *)tstr;
				ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
				                            OBEX_HDR_TIME, hv, len, 0);
				if (ret < 0) {
					ret = -1;
					OBEX_ObjectSetRsp (object, OBEX_RSP_INTERNAL_SERVER_ERROR, OBEX_RSP_INTERNAL_SERVER_ERROR);
					goto out;
				}

			}
		}

		/* Add a length header */
		if (object_size > 0) {
			obex_context->target_size = object_size;
			hv.bq4 = (uint32_t)object_size;
			ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
			                            OBEX_HDR_LENGTH, hv, 4, 0);
			if (ret < 0) {
				ret = -1;
				OBEX_ObjectSetRsp (object, OBEX_RSP_INTERNAL_SERVER_ERROR, OBEX_RSP_INTERNAL_SERVER_ERROR);
				goto out;
			}
		} else {
			obex_context->target_size = 0;
		}
	} else if (obex_context->type) {
		/* Don't report progress for object GET by type */
		obex_context->report_progress = FALSE;
		if (!strcmp (obex_context->type, LST_TYPE)) {
			gchar *new_path = NULL;

			g_message ("Serving FOLDER LISTING object");
			if (obex_context->remote) {
				/* We need to use some subfolder if we have NAME header */
				new_path = g_build_filename (current_path,
				                             obex_context->remote, NULL);
				if (!g_file_test (new_path, G_FILE_TEST_IS_DIR)) {
					g_free (new_path);
					ret = -1;
					OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_FOUND, OBEX_RSP_NOT_FOUND);
					goto out;
				}
			}
			/* write folder listing to buffer */
			obex_context->buf = (guchar*) get_folder_listing (
			                        new_path ? new_path : current_path,
			                        root_path, allow_write);
			g_free (new_path);
		} else if (!strcmp (obex_context->type, CAP_TYPE)) {
			g_message ("Serving CAPABILITY object");
			obex_context->buf = (guchar*) ods_get_capability (root_path);
		} else if (!strcmp (obex_context->type, BIP_CAPABILITIES_TYPE)) {
			g_message ("Serving IMAGING CAPABILITIES object");
			obex_context->buf = (guchar*) ods_get_imaging_capabilities ();
		} else {
			/* currently no other types are supported */
			ret = -1;
			OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_IMPLEMENTED, OBEX_RSP_NOT_IMPLEMENTED);
			goto out;
		}
		if (!obex_context->buf) {
			ret = -1;
			OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_FOUND, OBEX_RSP_NOT_FOUND);
			goto out;
		}
		g_message ("Object: %s", (gchar*) obex_context->buf);
		obex_context->buf_size = strlen ((gchar*) obex_context->buf);
		g_message ("Object length: %" G_GUINT64_FORMAT, obex_context->buf_size);
	} else {
		/* neither name nor type was specified */
		ret = -1;
		OBEX_ObjectSetRsp (object, OBEX_RSP_BAD_REQUEST, OBEX_RSP_BAD_REQUEST);
		goto out;
	}

	/* Add body header */
	hv.bs = NULL;
	ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
	                            OBEX_HDR_BODY, hv, 0, OBEX_FL_STREAM_START);
out:
	if (ret < 0){
		g_message("---------------ods_obex_srv_get error-----------------");
		ods_obex_transfer_close (obex_context);
	}
	else
		OBEX_ObjectSetRsp (object, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
	return ret;
}

static gint
ods_obex_put_full (OdsObexContext *obex_context,
                   const gchar *local, const gchar *remote,
                   const gchar *type, const gchar *img_description,
                   const gchar *img_handle, const guchar *apparam,
                   guint apparam_len, guint64 size, time_t mtime,
                   gboolean is_fifo, gint fifo_fd)
{
	gint				ret;
	obex_headerdata_t	hv;
	obex_object_t		*object = NULL;
	gchar				*uname = NULL;
	gsize				uname_len = 0;
	gchar				*uhandle = NULL;
	gsize				uhandle_len = 0;
	off_t				object_size = 0;
	time_t				object_time = -1;

	g_assert (remote || type);

	ods_obex_transfer_new (obex_context, local, remote, type);

	obex_context->img_handle = g_strdup (img_handle);

	/* get UTF16 name for remote file */
	if (remote) {
		uname_len = ods_filename_to_utf16 (&uname, remote);
		if (uname == NULL) {
			ret = -EINVAL;
			goto out;
		}
	}

	/* get UTF16 version of img_handle */
	if (img_handle) {
		uhandle_len = ods_filename_to_utf16 (&uhandle, img_handle);
		if (uhandle == NULL) {
			ret = -EINVAL;
			goto out;
		}
	}

	/* open local file, allocate buffer */
	if (local) {
		int oflags = O_RDONLY;

		if (is_fifo)
			oflags |= O_NONBLOCK;
		if (is_fifo && fifo_fd > -1)
			obex_context->stream_fd = fifo_fd;
		else
			obex_context->stream_fd = open (local, oflags);

		if (obex_context->stream_fd < 0) {
			ret = -errno;
			goto out;
		}
		if (is_fifo) {
			GIOChannel *chan;

			/* Setup IO watch to know when it is possible to write to FIFO or error happens */
			chan = g_io_channel_unix_new (obex_context->stream_fd);
			obex_context->fifo_watch = g_io_add_watch (chan,
			                           G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			                           fifo_watch, obex_context);
			g_io_channel_unref (chan);
		}
		/* Allocate buffer */
		obex_context->buf = g_malloc (obex_context->tx_max);
		obex_context->buf_size = obex_context->tx_max;
	} else {
		obex_context->report_progress = FALSE;
	}

	object = OBEX_ObjectNew (obex_context->obex_handle, OBEX_CMD_PUT);
	if (!object) {
		ret = -ENOMEM;
		goto out;
	}

	/* Add connection header */
	if (obex_context->connection_id != CONID_INVALID) {
		hv.bq4 = obex_context->connection_id;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_CONNECTION, hv, 4, 0);
		if (ret < 0)
			goto out;
	}

	/* Add name header */
	if (uname) {
		hv.bs = (guchar *) uname;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_NAME, hv, uname_len, 0);
		if (ret < 0)
			goto out;
		
		if(obex_context->protocol==L2CAP_OBEX){
			/*if have file name, then add SRM header*/
			hv.bq1 = OBEX_SRM_ENABLE;
			ret = OBEX_ObjectAddHeader(obex_context->obex_handle, object,
					OBEX_HDR_SRM, hv, 1,
					0);
			
			if (ret < 0)
				goto out;
		}
	}

	/* Add type header */
	if (type) {
		hv.bs = (guchar *)type;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_TYPE, hv, strlen(type) + 1, 0);
		if (ret < 0)
			goto out;
	}

	/* Try to figure out modification time and size */
	if (obex_context->stream_fd >= 0 && !img_handle && !img_description) {
		/* we don't send TIME and LENGTH headers for BIP functions */
		if (is_fifo) {
			/* if this is FIFO, we use supplied size and time instead of stat */
			object_size = size;
			object_time = mtime;
		} else {
			struct stat stats;
			if (fstat (obex_context->stream_fd, &stats) == 0) {
				object_size = stats.st_size;
				object_time = stats.st_mtime;
			}
		}
		obex_context->modtime = object_time;
	}

	/* Add a time header */
	if (object_time != -1) {
		gchar tstr[17];
		gint len;

		len = ods_make_iso8601 (object_time, tstr, sizeof (tstr));

		if (len >= 0) {
			hv.bs = (guchar *)tstr;
			ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
			                            OBEX_HDR_TIME, hv, len, 0);
			if (ret < 0)
				goto out;
		}
	}

	/* Add a length header */
	if (object_size > 0) {
		obex_context->target_size = object_size;
		hv.bq4 = (uint32_t)object_size;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_LENGTH, hv, 4, 0);
		if (ret < 0)
			goto out;
	} else {
		/* set target_size without sending length header (for BIP) */
		obex_context->target_size = size;
	}

	/* Add Img-Description header */
	if (img_description) {
		hv.bs = (guchar *)img_description;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_IMG_DESCRIPTOR, hv,
		                            strlen (img_description), 0);
		if (ret < 0)
			goto out;
	}

	/* Add Img-Handle header */
	if (uhandle) {
		hv.bs = (guchar *)uhandle;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_IMG_HANDLE, hv,
		                            uhandle_len, 0);
		if (ret < 0)
			goto out;
	}

	/* Add Application-Parameters header */
	if (apparam) {
		hv.bs = apparam;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_APPARAM, hv,
		                            apparam_len, 0);
		if (ret < 0)
			goto out;
	}

	/* Add body header */
	if (obex_context->stream_fd >= 0) {
		hv.bs = NULL;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_BODY, hv, 0, OBEX_FL_STREAM_START);
		if (ret < 0)
			goto out;
	}

	ret = ods_obex_send (obex_context, object);
out:
	if (uname_len > 0)
		g_free (uname);
	if (uhandle_len > 0)
		g_free (uhandle);
	if (ret < 0 && object)
		OBEX_ObjectDelete (obex_context->obex_handle, object);
	if (ret < 0)
		ods_obex_transfer_close (obex_context);

	return ret;
}

gint
ods_obex_put (OdsObexContext *obex_context,
              const gchar *local, const gchar *remote,
              const gchar *type, guint64 size, time_t mtime,
              gboolean is_fifo, gint fifo_fd)
{
	return ods_obex_put_full (obex_context, local, remote, type,
	                          NULL, NULL, NULL, 0, size, mtime,
	                          is_fifo, fifo_fd);
}

static void
ods_obex_srv_put_image (OdsObexContext *obex_context,
                        const gchar *img_descriptor)
{
	gchar	*encoding = NULL;
	gchar	*pixel = NULL;
	guint64	size = 0;
	gchar	*transformation = NULL;

	parse_image_descriptor (img_descriptor, &encoding, &pixel, &size,
	                        &transformation);
	obex_context->target_size = size;
	if (encoding)
		ods_obex_transfer_add_info (obex_context, "Encoding", encoding);
	if (pixel)
		ods_obex_transfer_add_info (obex_context, "Pixel", pixel);
	if (transformation)
		ods_obex_transfer_add_info (obex_context, "Transformation", transformation);
}

static void
ods_obex_srv_put_linked_thumbnail (OdsObexContext *obex_context)
{
	/* make remote filename the same as image handle */
	obex_context->remote = g_strdup (obex_context->img_handle);
}

static void
ods_obex_srv_put_linked_attachment (OdsObexContext *obex_context,
                                    const gchar *img_descriptor)
{
	gchar	*name = NULL;
	guint64	size = 0;
	gchar	*content_type = NULL;
	gchar	*charset = NULL;
	gchar	*created = NULL;

	parse_attachment_descriptor (img_descriptor, &name, &size, &content_type,
	                             &charset, &created);
	if (!name)
		name = g_strdup (ATTACHMENT_FILENAME);
	obex_context->remote = name;
	obex_context->target_size = size;
	if (content_type)
		ods_obex_transfer_add_info (obex_context, "ContentType", content_type);
	if (charset)
		ods_obex_transfer_add_info (obex_context, "Charset", charset);
	if (created)
		ods_obex_transfer_add_info (obex_context, "Created", created);
}

static gboolean
ods_obex_srv_remote_display (OdsObexContext *obex_context,
                             guchar *apparam, guint apparam_len, guint8 *action)
{
	bip_apparam_remote_display_t	*apparam_hdr;

	g_assert (action);
	if (apparam_len != sizeof (bip_apparam_remote_display_t)) {
		/* Invalid application parameters header */
		return FALSE;
	}
	apparam_hdr = (bip_apparam_remote_display_t*) apparam;
	if (apparam_hdr->tag_id != BIP_APPARAM_REMOTEDISPLAY_TAGID) {
		/* Invalid TagID */
		return FALSE;
	}
	*action = apparam_hdr->value;
	return TRUE;
}

gint
ods_obex_srv_put (OdsObexContext *obex_context, obex_object_t *object,
                  const gchar *path, guint8 *action, gboolean no_response_on_success)
{
	obex_headerdata_t	hv;
	uint8_t				hi;
	guint				hlen;
	gint				ret = 0;
	guint				written = 0;
	gint				write_ret;
	gboolean			is_delete = TRUE;
	gchar				*img_descriptor = NULL;
	guchar				*apparam = NULL;
	guint				apparam_len = 0;

	while (OBEX_ObjectGetNextHeader(obex_context->obex_handle, object,
	                                &hi, &hv, &hlen)) {
		g_message ("header: %d", hi);
		switch (hi) {
			case OBEX_HDR_BODY:
				is_delete = FALSE;
				g_message ("HDR_BODY length=%u", hlen);
				break;

			case OBEX_HDR_NAME:
				obex_context->remote = ods_filename_from_utf16 ((gchar *) hv.bs, hlen);
				g_message ("HDR_NAME: %s", obex_context->remote);
				break;

			case OBEX_HDR_TYPE:
				if (hv.bs[hlen - 1] != '\0' ||
				        !g_utf8_validate ((const gchar *) hv.bs, -1, NULL)) {
					/* invalid type header */
					g_message ("HDR_TYPE invalid: %s", (gchar*) hv.bs);
				}
				else {
					obex_context->type = g_strdup ((const gchar *) hv.bs);
					is_delete = FALSE;
					g_message ("HDR_TYPE: %s", obex_context->type);
				}
				break;

			case OBEX_HDR_LENGTH:
				obex_context->target_size = hv.bq4;
				is_delete = FALSE;
				g_message ("HDR_LENGTH: %" G_GUINT64_FORMAT, obex_context->target_size);
				break;

			case OBEX_HDR_TIME:
				obex_context->modtime = ods_parse_iso8601 ((gchar*) hv.bs, hlen);
				is_delete = FALSE;
				g_message ("HDR_TIME");
				break;

			case OBEX_HDR_DESCRIPTION:
				/* Not very useful info */
				break;

			case OBEX_HDR_COUNT:
				/* This informs us how many objects client is going to send
				 * during this session. We really don't care. */
				break;

			case OBEX_HDR_CONNECTION:
				if (obex_context->connection_id != CONID_INVALID &&
				        hv.bq4 != obex_context->connection_id) {
					/* wrong connection id */
					ret = -1;
					OBEX_ObjectSetRsp (object, OBEX_RSP_BAD_REQUEST, OBEX_RSP_BAD_REQUEST);
					goto out;
				}
				break;

			case OBEX_HDR_IMG_DESCRIPTOR:
				/* BIP-specific Img-Description header */
				img_descriptor = g_malloc0 (hlen+1);/* allocate one more byte for terminating \0 */
				memcpy (img_descriptor, hv.bs, hlen);
				break;

			case OBEX_HDR_IMG_HANDLE:
				/* BIP-specific Img-Handle header */
				obex_context->img_handle = ods_filename_from_utf16 ((gchar *) hv.bs, hlen);
				g_message ("HDR_IMG_HANDLE: %s", obex_context->img_handle);
				break;

			case OBEX_HDR_APPARAM:
				/* application parameters header */
				apparam_len = hlen;
				apparam = g_malloc (apparam_len);
				memcpy (apparam, hv.bs, apparam_len);
				break;
			case OBEX_HDR_SRM:
				if(obex_context->protocol==RFCOMM_OBEX)
					break;
				if (hv.bq1 == OBEX_SRM_ENABLE) {
					hv.bq1 = OBEX_SRM_ENABLE;
					OBEX_ObjectAddHeader(obex_context->obex_handle, object,
							OBEX_HDR_SRM, hv, 1,
							OBEX_FL_FIT_ONE_PACKET);
					OBEX_SetEnableSRM(object);
					g_message("ods_obex_srv_put Enable srm");
				} 
				else if (hv.bq1 == OBEX_SRM_ADVERTISE) {
					hv.bq1 = OBEX_SRM_ENABLE;
					OBEX_ObjectAddHeader(obex_context->obex_handle, object,
							OBEX_HDR_SRM, hv, 1,
							OBEX_FL_FIT_ONE_PACKET);				
				}
				break;			

			default:
				break;
		}
	}
	OBEX_ObjectReParseHeaders (obex_context->obex_handle, object);

	/* Call helper functions to deal with specific data */
	if (obex_context->connection_id != CONID_INVALID && obex_context->type) {
		if (!g_ascii_strncasecmp (obex_context->type, BIP_IMG_TYPE,
		                          strlen (obex_context->type))) {
			/* PutImage was requested */
			ods_obex_srv_put_image (obex_context, img_descriptor);
		} else if (!g_ascii_strncasecmp (obex_context->type, BIP_THM_TYPE,
		                                 strlen (obex_context->type))) {
			/* PutLinkedThumbnail was requested */
			ods_obex_srv_put_linked_thumbnail (obex_context);
		} else if (!g_ascii_strncasecmp (obex_context->type, BIP_ATTACHMENT_TYPE,
		                                 strlen (obex_context->type))) {
			/* PutLinkedAttachment was requested */
			ods_obex_srv_put_linked_attachment (obex_context, img_descriptor);
		} else if (!g_ascii_strncasecmp (obex_context->type, BIP_DISPLAY_TYPE,
		                                 strlen (obex_context->type))) {
			/* RemoteDisplay was requested */
			if (!ods_obex_srv_remote_display (obex_context, apparam,
			                                  apparam_len, action)) {
				obex_context->report_progress = FALSE;
				ret = -1;
				OBEX_ObjectSetRsp (object, OBEX_RSP_BAD_REQUEST, OBEX_RSP_BAD_REQUEST);
				goto out;
			}
		}
	}

	g_message ("path: %s", path);
	/* Open file for writing only if this is not a delete request */
	if (!is_delete) {
		if (!ods_obex_srv_new_file (obex_context, path)) {
			ret = -1;
			OBEX_ObjectSetRsp (object, OBEX_RSP_UNAUTHORIZED, OBEX_RSP_UNAUTHORIZED);
			goto out;
		}
	} else {
		/* this is a delete request */
		g_message ("this is a delete request ");
		obex_context->report_progress = FALSE;
		obex_context->local = g_build_filename (path, obex_context->remote, NULL);

		if (!g_file_test (obex_context->local, G_FILE_TEST_EXISTS)) {
			ret = -1;
			OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_FOUND, OBEX_RSP_NOT_FOUND);
			goto out;
		}
		if (g_access (obex_context->local, W_OK) < 0) {
			ret = -1;
			OBEX_ObjectSetRsp (object, OBEX_RSP_UNAUTHORIZED, OBEX_RSP_UNAUTHORIZED);
			goto out;
		}

		g_message ("Deleting: %s", obex_context->local);
		if (g_file_test (obex_context->local, G_FILE_TEST_IS_DIR))
			ret = rmdir (obex_context->local);
		else
			ret = g_unlink (obex_context->local);

		if (ret == -1)
			OBEX_ObjectSetRsp (object, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
	}

	/* If there is some data received already, write it to file */
	while (written < obex_context->buf_size) {
		write_ret = write (obex_context->stream_fd, obex_context->buf + written,
		                   obex_context->buf_size - written);
		if (write_ret < 0 && errno == EINTR)
			continue;

		if (write_ret < 0) {
			ret = -errno;
			OBEX_ObjectSetRsp (object, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
			break;
		}

		written += write_ret;
	}

out:
	g_free (img_descriptor);
	g_free (apparam);
	if (ret < 0)
		ods_obex_transfer_close (obex_context);
	else
		if (!no_response_on_success)
			OBEX_ObjectSetRsp (object, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
	return ret;
}

gint
ods_obex_setpath (OdsObexContext *obex_context, const gchar *path,
                  gboolean create)
{
	gint				ret;
	obex_headerdata_t	hv;
	obex_object_t		*object = NULL;
	obex_setpath_hdr_t	nonhdrdata;
	gchar				*uname;
	gsize				uname_len;

	nonhdrdata.flags = 0x02;
	nonhdrdata.constants = 0;

	if (strcmp (path, "..") == 0) {
		/* move up one directory */
		nonhdrdata.flags = 0x03;
		uname_len = 0;
	} else {
		/* normal directory change */
		uname_len = ods_filename_to_utf16 (&uname, path);
		if (uname == NULL) {
			ret = -EINVAL;
			goto out;
		}
	}

	/* Add create flag */
	if (create)
		nonhdrdata.flags &= ~0x02;

	object = OBEX_ObjectNew (obex_context->obex_handle, OBEX_CMD_SETPATH);
	if (!object) {
		ret = -ENOMEM;
		goto out;
	}

	/* Attach flags */
	ret = OBEX_ObjectSetNonHdrData (object, (uint8_t*)&nonhdrdata, 2);
	if (ret < 0)
		goto out;

	/* Add connection header */
	if (obex_context->connection_id != CONID_INVALID) {
		hv.bq4 = obex_context->connection_id;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_CONNECTION, hv, 4, 0);
		if (ret < 0)
			goto out;
	}

	/* Add name header */
	hv.bs = (guchar *) uname;
	ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
	                            OBEX_HDR_NAME, hv, uname_len, 0);
	if (ret < 0)
		goto out;

	ret = ods_obex_send (obex_context, object);
out:
	if (uname_len > 0 )
		g_free (uname);
	if (ret < 0 && object)
		OBEX_ObjectDelete (obex_context->obex_handle, object);
	return ret;
}

gboolean
ods_obex_srv_setpath (OdsObexContext *obex_context, obex_object_t *object,
                      const gchar *root_path, const gchar *current_path,
                      gchar **new_path,gboolean allow_write)
{
	uint8_t				*nonhdrdata_dummy = NULL;
	obex_setpath_hdr_t	*nonhdrdata;
	obex_headerdata_t	hv;
	uint8_t				hi;
	guint				hlen;
	gchar				*directory;
	gboolean			create = FALSE;
	gboolean			backup = FALSE;

	OBEX_ObjectGetNonHdrData (object, &nonhdrdata_dummy);
	if (!nonhdrdata_dummy) {
		OBEX_ObjectSetRsp (object, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return FALSE;
	}
	nonhdrdata = (obex_setpath_hdr_t*) nonhdrdata_dummy;

	if (nonhdrdata->flags == 0)
		create = TRUE;
	else if (nonhdrdata->flags == 0x03)
		backup = TRUE;
	else if (nonhdrdata->flags != 0x02) {
		OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_FOUND, OBEX_RSP_NOT_FOUND);
		return FALSE;
	}

	if (backup) {
		/* we have to go to parent directory */
		/* Check if we can't go up */
		if (strcmp (root_path, current_path) == 0) {
			OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_FOUND, OBEX_RSP_NOT_FOUND);
			return FALSE;
		}

		*new_path = g_path_get_dirname (current_path);
		OBEX_ObjectSetRsp (object, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		return TRUE;
	}

	while (OBEX_ObjectGetNextHeader (obex_context->obex_handle, object,
	                                 &hi, &hv, &hlen)) {
		if (hi == OBEX_HDR_NAME) {
			if (hlen > 0) {
				/* Normal directory change */
				directory = ods_filename_from_utf16 ((gchar *) hv.bs, hlen);
				*new_path = g_build_filename (current_path, directory, NULL);
				g_free (directory);
				/* Check if such path exists */
				if (g_file_test (*new_path, G_FILE_TEST_EXISTS)) {
					if (create) {
						g_free (*new_path);
						*new_path = ods_obex_get_new_path (current_path,
						                                   directory);

					} else {
						OBEX_ObjectSetRsp (object, OBEX_RSP_SUCCESS,
						                   OBEX_RSP_SUCCESS);
						return TRUE;
					}
				} else if (!create) {

					g_free (*new_path);
					OBEX_ObjectSetRsp (object, OBEX_RSP_NOT_FOUND,
					                   OBEX_RSP_NOT_FOUND);
					return FALSE;
				}
				/* In case we are Creating new folder */
				if(allow_write){
					if (mkdir (*new_path, 0755) == 0) {
						OBEX_ObjectSetRsp (object, OBEX_RSP_SUCCESS,
						                   OBEX_RSP_SUCCESS);
						return TRUE;
					} 
				}
				OBEX_ObjectSetRsp (object, OBEX_RSP_FORBIDDEN,
				                   OBEX_RSP_FORBIDDEN);
				return FALSE;
				
			} else {
				/* Name header empty, change path to root */
				*new_path = g_strdup (root_path);
				OBEX_ObjectSetRsp (object, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
				return TRUE;
			}
		}
	}

	/* invalid headers? */
	OBEX_ObjectSetRsp (object, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
	return FALSE;
}

gint
ods_obex_put_image (OdsObexContext *obex_context,
                    const gchar *local, const gchar *remote,
                    const gchar *encoding, const gchar *pixel,
                    guint64 size, const gchar *transformation)
{
	gchar	*img_descriptor;
	gint	ret;

	g_assert (local && remote && encoding && pixel && transformation);

	img_descriptor = get_image_descriptor (encoding, pixel, size, transformation);
	ret = ods_obex_put_full (obex_context, local, remote, BIP_IMG_TYPE,
	                         img_descriptor, NULL, NULL, 0, size, -1, FALSE, -1);
	if (*encoding != '\0')
		ods_obex_transfer_add_info (obex_context, "Encoding",
		                            g_strdup (encoding));
	if (*pixel != '\0')
		ods_obex_transfer_add_info (obex_context, "Pixel", g_strdup (pixel));
	if (*transformation != '\0')
		ods_obex_transfer_add_info (obex_context, "Transformation",
		                            g_strdup (transformation));

	g_free (img_descriptor);
	return ret;
}

gint
ods_obex_put_linked_thumbnail (OdsObexContext *obex_context,
                               const gchar *local, const gchar *img_handle,
                               guint64 size)
{
	g_assert (local && img_handle);

	return ods_obex_put_full (obex_context, local, NULL, BIP_THM_TYPE,
	                          NULL, img_handle, NULL, 0, size, -1, FALSE, -1);
}

gint
ods_obex_put_linked_attachment (OdsObexContext *obex_context,
                                const gchar *local, const gchar *img_handle,
                                const gchar *name, const gchar *content_type,
                                const gchar *charset, guint64 size, time_t ctime)
{
	gchar	*att_descriptor;
	gint	ret;
	struct stat stats;
	guint64	object_size = 0;
	time_t	object_ctime = -1;
	gchar	created_time[17];

	g_assert (local && img_handle && name && content_type && charset);

	if (size > 0) {
		object_size = size;
		object_ctime = ctime;
	} else if (g_stat (local, &stats) == 0) {
		object_size = stats.st_size;
		object_ctime = stats.st_ctime;
	}
	if (object_ctime != -1)
		ods_make_iso8601 (ctime, created_time, sizeof (created_time));
	att_descriptor = get_attachment_descriptor(name, object_size, content_type, charset,
	                 object_ctime!=-1 ? created_time : "");
	ret = ods_obex_put_full (obex_context, local, NULL, BIP_ATTACHMENT_TYPE,
	                         att_descriptor, img_handle, NULL, 0, object_size,
	                         -1, FALSE, -1);
	obex_context->remote = g_strdup (name);/* set it here so that we don't send NAME header*/
	if (*content_type != '\0')
		ods_obex_transfer_add_info (obex_context, "ContentType",
		                            g_strdup (content_type));
	if (*charset != '\0')
		ods_obex_transfer_add_info (obex_context, "Charset", g_strdup (charset));
	if (ctime != -1)
		ods_obex_transfer_add_info (obex_context, "Created",
		                            g_strdup (created_time));

	g_free (att_descriptor);
	return ret;
}

/* img_handle must not be NULL, must be empty when action != SelectImage */
gint
ods_obex_remote_display (OdsObexContext *obex_context,
                         const gchar *img_handle, guint8 action)
{
	bip_apparam_remote_display_t	*apparam_hdr;
	gint							ret;

	g_assert (img_handle);

	apparam_hdr = g_new0 (bip_apparam_remote_display_t, 1);
	apparam_hdr->tag_id = BIP_APPARAM_REMOTEDISPLAY_TAGID;
	apparam_hdr->length = 1;
	apparam_hdr->value = action;
	ret = ods_obex_put_full (obex_context, NULL, NULL, BIP_DISPLAY_TYPE,
	                         NULL, img_handle, (guchar *) apparam_hdr,
	                         sizeof (bip_apparam_remote_display_t), 0,
	                         -1, FALSE, -1);
	g_free (apparam_hdr);
	return ret;
}

gint
ods_obex_action (OdsObexContext *obex_context, const gchar *src,
                 const gchar *dst, guint8 action, guint32 perms)
{
	gint ret;
	obex_object_t *object;
	obex_headerdata_t hv;
	gchar	*uname;
	gsize	uname_len;

	if (action != OBEX_ACTION_SETPERM)
		g_assert (src && dst);

	object = OBEX_ObjectNew (obex_context->obex_handle, OBEX_CMD_ACTION);

	/* Add connection header */
	if (obex_context->connection_id != CONID_INVALID) {
		hv.bq4 = obex_context->connection_id;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_CONNECTION, hv, 4, 0);
		if (ret < 0)
			goto out;
	}

	/* src header */
	uname_len = ods_filename_to_utf16 (&uname, src);
	if (uname == NULL) {
		ret = -EINVAL;
		goto out;
	}
	hv.bs = (guchar *) uname;
	ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
	                            OBEX_HDR_NAME, hv, uname_len, 0);
	g_free (uname);
	if (ret < 0)
		goto out;

	/* dst header */
	uname_len = ods_filename_to_utf16 (&uname, dst);
	if (uname == NULL) {
		ret = -EINVAL;
		goto out;
	}
	hv.bs = (guchar *) uname;
	ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
	                            OBEX_HDR_DESTNAME, hv, uname_len, 0);
	g_free (uname);
	if (ret < 0)
		goto out;

	/* action header */
	hv.bq1 = action;
	OBEX_ObjectAddHeader (obex_context->obex_handle, object,
	                      OBEX_HDR_ACTION_ID, hv, 1, 0);

	/* permissions header */
	if (action == OBEX_ACTION_SETPERM) {
		hv.bq4 = perms;
		ret = OBEX_ObjectAddHeader (obex_context->obex_handle, object,
		                            OBEX_HDR_PERMISSIONS, hv, 4, 0);
		if (ret < 0)
			goto out;
	}

	ret = ods_obex_send (obex_context, object);
out:
	if (ret < 0 && object)
		OBEX_ObjectDelete (obex_context->obex_handle, object);
	return ret;
}

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

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "ods-bluez.h"
#include "ods-common.h"
#include "ods-error.h"

static gboolean sdp_initiate_search		(OdsBluezCancellable *ctxt);

static GHashTable *sdp_session_list = NULL;
typedef struct SdpSessionRecords_ {
	sdp_session_t	*session;
	guint			rec_count;
} SdpSessionRecords;

static void
ods_bluez_cancellable_free (OdsBluezCancellable *cb_data)
{
	g_io_channel_unref (cb_data->io_channel);
	sdp_close (cb_data->session);
	g_free (cb_data->imagingdata);
	g_free (cb_data);
}

static gboolean
client_socket_connect_cb (GIOChannel *io_channel, GIOCondition cond,
                          OdsBluezCancellable *cb_data)
{
	OdsBluezFunc	cb = cb_data->cb;
	gint			fd;
	gint			ret_fd = -1;
	GError			*error = NULL;

	fd = g_io_channel_unix_get_fd (io_channel);
	/* Evaluate the connection condition */
	if (cond == G_IO_OUT) {
		/* Connection successful */
		ret_fd = fd;
	} else if (cond == (G_IO_OUT | G_IO_HUP)) {
		/* The connection timed out. */
		g_set_error (&error, ODS_ERROR, ODS_ERROR_CONNECTION_TIMEOUT, "Connection timed out");
	} else if (cond == (G_IO_OUT | G_IO_HUP | G_IO_ERR)) {
		/* The connection was refused */
		g_set_error (&error, ODS_ERROR, ODS_ERROR_CONNECTION_REFUSED, "Connection refused");
	} else {
		/* A generic unknown error occured during the connection attempt. */
		g_set_error (&error, ODS_ERROR, ODS_ERROR_CONNECTION_ATTEMPT_FAILED, "Connection failed");
	}

	if (ret_fd != -1)
		g_message ("Connected");
	else {
		close (fd);
		g_message ("Failed to connect");
	}
	cb (ret_fd, cb_data->channel, cb_data->imagingdata, error, cb_data->cb_data);

	ods_bluez_cancellable_free (cb_data);
	g_clear_error (&error);

	return FALSE;
}

static void
rfcomm_connect (OdsBluezCancellable *cb_data, gint channel)
{
	OdsBluezFunc		cb = cb_data->cb;
	GError				*error = NULL;
	struct sockaddr_rc	addr;
	int					fd = -1;
	GIOChannel			*io_channel = NULL;

	/* Create socket and start connecting */
	fd = socket (AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (fd < 0) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_CONNECTION_ATTEMPT_FAILED,
		             "Could not create socket");
		goto err;
	}

	memset (&addr, 0, sizeof(addr));
	/* source address */
	addr.rc_family  = AF_BLUETOOTH;
	bacpy (&addr.rc_bdaddr, &cb_data->source_address);

	if (bind (fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
		g_set_error (&error, ODS_ERROR,
		             ODS_ERROR_CONNECTION_ATTEMPT_FAILED,
		             "Binding to local device failed (errno: %d)", errno);
		goto err;
	}

	memset (&addr, 0, sizeof(addr));
	/* destination address */
	addr.rc_family  = AF_BLUETOOTH;
	addr.rc_channel = channel;
	bacpy (&addr.rc_bdaddr, &cb_data->target_address);

	/* Use non-blocking connect */
	fcntl (fd, F_SETFL, O_NONBLOCK);
	io_channel = g_io_channel_unix_new (fd);

	if (connect (fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		/* BlueZ returns EAGAIN eventhough it should return EINPROGRESS */
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			g_set_error (&error, ODS_ERROR,
			             ODS_ERROR_CONNECTION_ATTEMPT_FAILED,
			             "Connecting to remote device failed");
			goto err;
		}

		g_message ("Connect in progress");
		cb_data->io_watch = g_io_add_watch (io_channel,
		                                    G_IO_OUT | G_IO_ERR | G_IO_NVAL | G_IO_HUP,
		                                    (GIOFunc) client_socket_connect_cb, cb_data);
		cb_data->fd = fd;
	} else {
		/* Connect succeeded with first try */
		g_message ("Connect on first try");
		client_socket_connect_cb (io_channel, G_IO_OUT, cb_data);
	}
	g_io_channel_unref (io_channel);
	return;

err:
	if (io_channel)
		g_io_channel_unref (io_channel);
	if (fd >= 0)
		close (fd);
	cb (-1, cb_data->channel, cb_data->imagingdata, error, cb_data->cb_data);
	ods_bluez_cancellable_free (cb_data);
	g_clear_error (&error);
}


static void
sdp_get_channel (sdp_record_t *sdp_record,
                 OdsBluezCancellable *cb_data)
{
	OdsBluezFunc		cb = cb_data->cb;
	GError				*error = NULL;
	sdp_list_t			*protos = NULL;
	gint				channel = -1;

	g_message ("getting RFCOMM channel");
	/* get channel for this service */
	if (sdp_get_access_protos (sdp_record, &protos) != 0) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "Could not get service channel");
		goto err;
	}

	channel = sdp_get_proto_port (protos, RFCOMM_UUID);
	cb_data->channel = channel;

	if (cb_data->uuid.value.uuid16 == IMAGING_RESPONDER_SVCLASS_ID) {
		/* BIP only */
		sdp_data_t		*sdpdata;

		cb_data->imagingdata = g_new0 (ImagingSdpData, 1);
		sdpdata = sdp_data_get (sdp_record, SDP_ATTR_SUPPORTED_CAPABILITIES);
		cb_data->imagingdata->supp_capabilities = sdpdata->val.uint8;
		g_message ("supp_capabilities: %d", cb_data->imagingdata->supp_capabilities);

		sdpdata = sdp_data_get (sdp_record, SDP_ATTR_SUPPORTED_FEATURES);
		cb_data->imagingdata->supp_features = sdpdata->val.uint16;
		g_message ("supp_features: %d", cb_data->imagingdata->supp_features);

		sdpdata = sdp_data_get (sdp_record, SDP_ATTR_SUPPORTED_FUNCTIONS);
		cb_data->imagingdata->supp_functions = sdpdata->val.uint32;
		g_message ("supp_funcs: %d", cb_data->imagingdata->supp_functions);

		sdpdata = sdp_data_get (sdp_record, SDP_ATTR_TOTAL_IMAGING_DATA_CAPACITY);
		cb_data->imagingdata->data_capacity = sdpdata->val.uint64;
		g_message ("data_cap: %" G_GUINT64_FORMAT, cb_data->imagingdata->data_capacity);

		if (!(cb_data->imaging_feature & cb_data->imagingdata->supp_features)) {
			g_set_error (&error, ODS_ERROR, ODS_ERROR_NOT_SUPPORTED,
			             "Selected imaging feature not supported");
			goto err;
		}
	}

	if (protos) {
		sdp_list_foreach (protos, (sdp_list_func_t)sdp_list_free, 0);
		sdp_list_free (protos, 0);
	}

	rfcomm_connect (cb_data, channel);
	return;

err:
	cb (-1, cb_data->channel, cb_data->imagingdata, error, cb_data->cb_data);
	ods_bluez_cancellable_free (cb_data);
	g_clear_error (&error);
}

static void sdp_search_completed_cb (uint8_t type, uint16_t status,
                                     uint8_t *rsp, size_t size,
                                     void *user_data)
{
	OdsBluezCancellable *ctxt = user_data;
	OdsBluezFunc cb = ctxt->cb;
	sdp_list_t *recs = NULL;
	guint scanned;
	int seqlen = 0, bytesleft = size;
	uint8_t dataType;
	GError *error = NULL;

	if (status || type != SDP_SVC_SEARCH_ATTR_RSP) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_CONNECTION_ATTEMPT_FAILED,
		             "Service search failed");
		goto done;
	}

	g_message ("SDP search completed");
#ifdef USE_BLUEZ3FUNCS
	/* Using Bluez 3.x */
	scanned = sdp_extract_seqtype_safe(rsp, bytesleft, &dataType, &seqlen);
#else
	/* Using Bluez 4.x */
	scanned = sdp_extract_seqtype(rsp, bytesleft, &dataType, &seqlen);
#endif /* USE_BLUEZ3FUNCS */

	if (!scanned) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_CONNECTION_ATTEMPT_FAILED,
		             "Service search failed");
		goto done;
	}

	rsp += scanned;
	bytesleft -= scanned;
	do {
		sdp_record_t *rec;
		int recsize;

		recsize = 0;
#ifdef USE_BLUEZ3FUNCS
		/* Using Bluez 3.x */
		rec = sdp_extract_pdu_safe(rsp, bytesleft, &recsize);
#else
		/* Using Bluez 4.x */
		rec = sdp_extract_pdu(rsp, bytesleft, &recsize);
#endif /* USE_BLUEZ3FUNCS */

		if (!rec)
			break;

		if (!recsize) {
			sdp_record_free(rec);
			break;
		}

		scanned += recsize;
		rsp += recsize;
		bytesleft -= recsize;

		recs = sdp_list_append(recs, rec);
	} while (scanned < size && bytesleft > 0);

	if (sdp_list_len (recs) == 0) {
		g_message ("no SDP records found");
		if (!memcmp (&ctxt->uuid.value.uuid128, OBEX_NOKIAFTP_UUID,
		             sizeof(uint128_t))) {
			g_message ("Using standard OBEX FTP uuid");
			sdp_uuid16_create (&ctxt->uuid, OBEX_FILETRANS_SVCLASS_ID);
			if (!sdp_initiate_search (ctxt))
				g_set_error (&error, ODS_ERROR, ODS_ERROR_CONNECTION_ATTEMPT_FAILED,
				             "Service search failed");
		} else {
			g_set_error (&error, ODS_ERROR, ODS_ERROR_NOT_SUPPORTED,
			             "Service not supported by remote device");
		}
	} else {
		sdp_record_print (recs->data);
		sdp_get_channel (recs->data, ctxt);
	}

done:
	if (error) {
		cb (-1, ctxt->channel, ctxt->imagingdata, error, ctxt->cb_data);
		ods_bluez_cancellable_free (ctxt);
		g_clear_error (&error);
	}
	if (recs)
		sdp_list_free(recs, (sdp_free_func_t) sdp_record_free);
}

static gboolean sdp_search_process_cb (GIOChannel *chan,
                                       GIOCondition cond, void *user_data)
{
	OdsBluezCancellable *ctxt = user_data;
	OdsBluezFunc cb = ctxt->cb;
	GError *error = NULL;

	g_message ("SDP search process");
	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_CONNECTION_ATTEMPT_FAILED,
		             "Service search failed");
		cb (-1, ctxt->channel, ctxt->imagingdata, error, ctxt->cb_data);
		ods_bluez_cancellable_free (ctxt);
		g_clear_error (&error);

		return FALSE;
	}

	if (sdp_process(ctxt->session) < 0) {
		/* search finished and search_completed_cb was called */
		return FALSE;
	}

	return TRUE;
}

static gboolean sdp_initiate_search (OdsBluezCancellable *ctxt)
{
	sdp_list_t *search, *attrids;
	uint32_t range = 0x0000ffff;
	gboolean ret = TRUE;

	/* Set callback responsible for calling sdp_process */
	ctxt->io_watch = g_io_add_watch(ctxt->io_channel,
	                                G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
	                                sdp_search_process_cb, ctxt);
	search = sdp_list_append(NULL, &ctxt->uuid);
	attrids = sdp_list_append(NULL, &range);
	if (sdp_service_search_attr_async(ctxt->session,
	                                  search, SDP_ATTR_REQ_RANGE, attrids) < 0) {
		ods_safe_gsource_remove (&ctxt->io_watch);
		ret = FALSE;
	}

	sdp_list_free(attrids, NULL);
	sdp_list_free(search, NULL);
	return ret;
}

static gboolean sdp_connect_watch (GIOChannel *chan, GIOCondition cond,
                                   gpointer user_data)
{
	OdsBluezCancellable *ctxt = user_data;

	socklen_t len;
	int sk, err = 0;
	GError *error = NULL;
	OdsBluezFunc cb = ctxt->cb;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(err);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
		goto failed;

	if (err != 0)
		goto failed;

	g_message ("Connected SDP session");
	if (sdp_set_notify(ctxt->session, sdp_search_completed_cb, ctxt) < 0)
		goto failed;

	if (!sdp_initiate_search (ctxt))
		goto failed;

	return FALSE;

failed:
	g_set_error (&error, ODS_ERROR, ODS_ERROR_CONNECTION_ATTEMPT_FAILED,
	             "Service search failed (%s)",
	             err ? strerror(err) : "Could not start search");
	cb (-1, ctxt->channel, ctxt->imagingdata, error, ctxt->cb_data);
	ods_bluez_cancellable_free (ctxt);
	g_clear_error (&error);

	return FALSE;
}

OdsBluezCancellable*
ods_bluez_get_client_socket (const bdaddr_t *dst,
                             const bdaddr_t *src,
                             const uuid_t *uuid,
                             guint imaging_feature,
                             gint channel,
                             OdsBluezFunc func,
                             gpointer data)
{
	OdsBluezCancellable *cb_data;

	cb_data = g_new0 (OdsBluezCancellable, 1);
	cb_data->cb = func;
	cb_data->cb_data = data;
	bacpy (&cb_data->target_address, dst);
	bacpy (&cb_data->source_address, src);
	cb_data->imaging_feature = imaging_feature;
	cb_data->channel = -1;
	cb_data->fd = -1;

	/* Discover channel for needed service only if we don't know it yet */
	if (channel == 0) {
		cb_data->session = sdp_connect (src, dst, SDP_NON_BLOCKING);
		if (!cb_data->session) {
			ods_bluez_cancellable_free (cb_data);
			return NULL;
		}

		cb_data->io_channel = g_io_channel_unix_new (
		                          sdp_get_socket (cb_data->session));
		cb_data->io_watch = g_io_add_watch (cb_data->io_channel,
		                                    G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
		                                    sdp_connect_watch, cb_data);

		/* From Johan Hedberg:
		 *
		 * some Nokia Symbian phones have two OBEX FTP services: one
		 * identified with the normal UUID and another with a Nokia specific
		 * 128 bit UUID. The service found behind the normal identifier is
		 * very limited in features on these phones while the other one
		 * supports full OBEX FTP (don't ask me why).
		 */
		/* if FTP was requested, use NOKIAFTP instead,
		 * if it isn't found we retreat to FTP in get_remote_service_handles_cb */
		if (uuid->value.uuid16 == OBEX_FILETRANS_SVCLASS_ID ||
		        !memcmp(&uuid->value.uuid128, OBEX_FTP_UUID, sizeof(uint128_t))) {
			g_message ("FTP uuid selected, first checking for Nokia OBEX PC Suite Services uuid");
			sdp_uuid128_create (&cb_data->uuid, OBEX_NOKIAFTP_UUID);
		} else
			memcpy (&cb_data->uuid, uuid, sizeof (uuid_t));

	} else {
		/* skip SDP requests and connect to specified RFCOMM channel */
		cb_data->channel = channel;
		rfcomm_connect (cb_data, channel);
	}

	return cb_data;
}

void
ods_bluez_cancel_get_client_socket (OdsBluezCancellable *cancel)
{
	OdsBluezFunc	cb = cancel->cb;
	GError			*error = NULL;

	/* cancel connecting */
	if (cancel->io_watch > 0) {
		if (cancel->fd >= 0)
			close (cancel->fd);
		ods_safe_gsource_remove (&cancel->io_watch);
	}
	/* callback */
	g_set_error (&error, ODS_ERROR, ODS_ERROR_CANCELLED,
	             "Cancelled by DBus client");
	cb (-1, cancel->channel, cancel->imagingdata, error, cancel->cb_data);
	g_clear_error (&error);
	ods_bluez_cancellable_free (cancel);
}

gint
ods_bluez_get_server_socket (const gchar *address, guint8 channel)
{
	struct sockaddr_rc addr;
	gint fd = -1;

	fd = socket (AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (fd < 0)
		goto err;

	memset (&addr, 0, sizeof(addr));
	addr.rc_family  = AF_BLUETOOTH;
	addr.rc_channel = channel;
	str2ba (address, &addr.rc_bdaddr);

	if (bind (fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
		goto err;
	}

	if (listen (fd, 1) < 0) {
		goto err;
	}

	return fd;
err:
	if (fd >= 0)
		close (fd);
	return -1;
}

static sdp_session_t*
sdp_session_get (const gchar *device, gboolean create_new)
{
	SdpSessionRecords *recs;
	sdp_session_t *session;
	bdaddr_t src;

	if (sdp_session_list &&
	        (recs = g_hash_table_lookup (sdp_session_list, device))) {
		return recs->session;
	}
	if (!create_new)
		return NULL;

	str2ba (device, &src);
	session = sdp_connect (&src, BDADDR_LOCAL, SDP_RETRY_IF_BUSY);
	if (!session) {
		g_warning ("Couldn't connect to SDP server");
		return NULL;
	}
	return session;
}

static void
sdp_session_list_add (const gchar *device, sdp_session_t *session)
{
	SdpSessionRecords *recs;

	if (!sdp_session_list) {
		sdp_session_list = g_hash_table_new_full (g_str_hash, g_str_equal,
		                   g_free, g_free);
	}
	if (!(recs = g_hash_table_lookup (sdp_session_list, device))) {
		recs = g_new0 (SdpSessionRecords, 1);
		recs->session = session;
		recs->rec_count = 1;
		g_hash_table_insert (sdp_session_list, g_strdup (device), recs);
	} else {
		recs->rec_count++;
	}
}

static void
sdp_session_list_remove (const gchar *device)
{
	SdpSessionRecords *recs;

	if (!sdp_session_list)
		return;
	if (!(recs = g_hash_table_lookup (sdp_session_list, device)))
		return;
	recs->rec_count--;
	if (recs->rec_count < 1) {
		sdp_close (recs->session);
		g_hash_table_remove (sdp_session_list, device);
	}
}

static guint32
add_bin_service_record (const gchar *device, sdp_record_t *rec)
{
	sdp_session_t *session;
	bdaddr_t src;
	gint ret;

	str2ba (device, &src);
	session = sdp_session_get (device, TRUE);
	if (!session)
		return 0;

	ret = sdp_device_record_register (session, &src, rec, 0);
	if (ret < 0) {
		g_warning("Failed to register sdp record, ret: %i", ret);
		return 0;
	}

	sdp_session_list_add (device, session);
	return rec->handle;
}

guint32
ods_bluez_add_service_record (const gchar *device, gint service,
                              ImagingSdpData *imagingdata)
{
	guint32 ret;
	/* vars that differ according to service */
	guint8 chan;
	guint16 svclass_id_;
	guint16 profile_id_;
	gchar *desc;
	/* --- */
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, l2cap_uuid, rfcomm_uuid, obex_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[3];
	sdp_data_t *channel;
	/* only for OPP */
	uint8_t formats[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF };
	void *dtds[sizeof(formats)], *values[sizeof(formats)];
	guint32 i;
	uint8_t dtd = SDP_UINT8;
	sdp_data_t *sflist;
	/* --- */
	/* only for BIP */
	sdp_data_t *supp_cap, *supp_feat, *supp_func, *data_cap;
	/* --- */
	sdp_record_t rec;

	switch (service) {
		case ODS_SERVICE_OPP:

			chan = ODS_OPP_RFCOMM_CHANNEL;
			svclass_id_ = OBEX_OBJPUSH_SVCLASS_ID;
			profile_id_ = OBEX_OBJPUSH_PROFILE_ID;
			desc = "OBEX Object Push";
			break;
		case ODS_SERVICE_FTP:
			chan = ODS_FTP_RFCOMM_CHANNEL;
			svclass_id_ = OBEX_FILETRANS_SVCLASS_ID;
			profile_id_ = OBEX_FILETRANS_PROFILE_ID;
			desc = "OBEX File Transfer";
			break;
		case ODS_SERVICE_PBAP:
			chan = ODS_PBAP_RFCOMM_CHANNEL;
			svclass_id_ = PBAP_PSE_SVCLASS_ID;
			profile_id_ = PBAP_PSE_PROFILE_ID;
			desc = "OBEX Phonebook Access";
			break;
		case ODS_SERVICE_BIP:
			chan = ODS_BIP_RFCOMM_CHANNEL;
			svclass_id_ = IMAGING_RESPONDER_SVCLASS_ID;
			profile_id_ = IMAGING_PROFILE_ID;
			desc = "Imaging";
			break;
		default:
			return 0;
	}
	memset (&rec, 0, sizeof(sdp_record_t));
	rec.handle = 0xffffffff;

	sdp_uuid16_create (&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append (0, &root_uuid);
	sdp_set_browse_groups (&rec, root);

	sdp_uuid16_create (&svclass_uuid, svclass_id_);
	svclass_id = sdp_list_append (0, &svclass_uuid);
	sdp_set_service_classes (&rec, svclass_id);

	sdp_uuid16_create (&profile[0].uuid, profile_id_);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append (0, profile);
	sdp_set_profile_descs (&rec, pfseq);

	sdp_uuid16_create (&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append (0, &l2cap_uuid);
	apseq = sdp_list_append (0, proto[0]);

	sdp_uuid16_create (&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append (0, &rfcomm_uuid);
	channel = sdp_data_alloc (SDP_UINT8, &chan);
	proto[1] = sdp_list_append (proto[1], channel);
	apseq = sdp_list_append (apseq, proto[1]);

	sdp_uuid16_create (&obex_uuid, OBEX_UUID);
	proto[2] = sdp_list_append (0, &obex_uuid);
	apseq = sdp_list_append (apseq, proto[2]);

	aproto = sdp_list_append (0, apseq);
	sdp_set_access_protos (&rec, aproto);

	if (service == ODS_SERVICE_OPP) {
		for (i = 0; i < sizeof(formats); i++) {
			dtds[i] = &dtd;
			values[i] = &formats[i];
		}
		sflist = sdp_seq_alloc (dtds, values, sizeof(formats));
		sdp_attr_add (&rec, SDP_ATTR_SUPPORTED_FORMATS_LIST, sflist);
	} else if (service == ODS_SERVICE_BIP) {
		g_assert (imagingdata != NULL);
		supp_cap = sdp_data_alloc (SDP_UINT8, &imagingdata->supp_capabilities);
		supp_feat = sdp_data_alloc (SDP_UINT16, &imagingdata->supp_features);
		supp_func = sdp_data_alloc (SDP_UINT32, &imagingdata->supp_functions);
		data_cap = sdp_data_alloc (SDP_UINT64, &imagingdata->data_capacity);
		sdp_attr_add (&rec, SDP_ATTR_SUPPORTED_CAPABILITIES, supp_cap);
		sdp_attr_add (&rec, SDP_ATTR_SUPPORTED_FEATURES, supp_feat);
		sdp_attr_add (&rec, SDP_ATTR_SUPPORTED_FUNCTIONS, supp_func);
		sdp_attr_add (&rec, SDP_ATTR_TOTAL_IMAGING_DATA_CAPACITY, data_cap);
	}

	sdp_set_info_attr (&rec, desc, 0, 0);

	ret = add_bin_service_record (device, &rec);

	sdp_list_free (root, NULL);
	sdp_list_free (svclass_id, NULL);
	sdp_list_free (pfseq, NULL);
	sdp_list_free (apseq, NULL);
	sdp_list_free (aproto, NULL);
	sdp_list_free (proto[0], NULL);
	sdp_list_free (proto[1], NULL);
	sdp_list_free (proto[2], NULL);
	sdp_data_free (channel);
	sdp_list_free (rec.attrlist, (sdp_free_func_t) sdp_data_free);
	sdp_list_free (rec.pattern, free);

	return ret;
}

void
ods_bluez_remove_service_record (const gchar *device, guint32 record_handle)
{
	sdp_session_t *session;
	bdaddr_t src;
	gint ret;

	str2ba (device, &src);
	session = sdp_session_get (device, FALSE);
	if (!session) {
		g_warning ("Couldn't get SDP session");
		return;
	}

	ret = sdp_device_record_unregister_binary (session,	&src, record_handle);
	if (ret)
		g_warning ("Failed to unregister service record");
	else
		g_message ("SDP service unregistered");

	sdp_session_list_remove (device);
}

void
ods_bluez_finalize ()
{
	if (sdp_session_list) {
		g_hash_table_unref (sdp_session_list);
		sdp_session_list = NULL;
	}
}

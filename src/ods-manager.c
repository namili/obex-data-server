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
#include <fcntl.h>
#include <string.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <openobex/obex.h>
#include <bluetooth/l2cap.h>

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-bindings.h>
#include <dbus/dbus-glib-lowlevel.h>


#include "ods-bluez.h"
#include "ods-common.h"
#include "ods-error.h"
#include "ods-server.h"
#include "ods-session.h"
#include "ods-marshal.h"
#include "ods-manager.h"
#include "ods-usb.h"
#include "ods-manager-dbus-glue.h"

#define ODS_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), ODS_TYPE_MANAGER, OdsManagerPrivate))

typedef struct OdsManagerSessionInfo_ {
	OdsSession	*session;
	/* Bluetooth specific */
	OdsBluezCancellable	*bluetooth_cancel_data;
	gchar				*bluetooth_target_address;
	gchar				*bluetooth_source_address;
	gint				bluetooth_channel;
	/* USB specific */
	gint				usb_interface_number;
	/* TTY specific */
	gchar				*tty_dev;
} OdsManagerSessionInfo;

typedef struct OdsManagerServerInfo_ {
	OdsServer	*server;
	/* Bluetooth specific */
	gchar		*bluetooth_source_address;
	gboolean	require_pairing;
	guint32		sdp_record_handle;
	/* TTY specific */
	gchar		*tty_dev;
} OdsManagerServerInfo;

typedef struct OdsManagerCreateSessionData_ {
	OdsManager	*manager;
	OdsSession	*session;
	gchar		*tty_dev;
} OdsManagerCreateSessionData;

struct OdsManagerPrivate {
	gboolean	is_disposing;
	gboolean	disposed;
	gboolean	initialized;
	/* Session list (DBus path as key and OdsManagerSessionInfo as value) */
	GHashTable	*session_list;
	/* Server list (DBus path as key and OdsManagerServerInfo as value) */
	GHashTable	*server_list;
	DBusGProxy	*dbus_proxy;
	GHashTable	*listened_dbus_names;
	GHashTable	*removed_dbus_names;
};

enum {
	SESSION_CONNECTED,
	SESSION_CLOSED,
	SESSION_CONNECT_ERROR,
	DISPOSED,
	LAST_SIGNAL
};

static guint	     signals [LAST_SIGNAL] = { 0, };

G_DEFINE_TYPE (OdsManager, ods_manager, G_TYPE_OBJECT)

static gboolean ods_manager_session_finalize (gpointer key,
        OdsManagerSessionInfo *session_info,
        OdsManager *manager);
static gboolean		ods_manager_server_finalize (gpointer key,
        OdsManagerServerInfo *server_info,
        OdsManager *manager);
static void     ods_manager_finalize	(GObject	 *object);


static void
ods_manager_listened_names_add (OdsManager *manager, const gchar *dbus_owner,
                                const gchar *dbus_path)
{
	GHashTable *object_list = NULL;

	if (!(object_list = g_hash_table_lookup (manager->priv->listened_dbus_names,
	                    dbus_owner))) {
		object_list = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
		g_hash_table_insert (manager->priv->listened_dbus_names, g_strdup (dbus_owner),
		                     object_list);
	}
	g_hash_table_insert (object_list, g_strdup (dbus_path), NULL);
}

static void
ods_manager_listened_names_remove (OdsManager *manager, const gchar *dbus_owner,
                                   const gchar *dbus_path)
{
	GHashTable *object_list;

	g_message ("Removing listened DBUS name %s (object: %s)", dbus_owner, dbus_path);
	if ((object_list = g_hash_table_lookup (manager->priv->listened_dbus_names,
	                                        dbus_owner))) {
		if (dbus_path) {
			g_hash_table_remove (object_list, dbus_path);
			if (g_hash_table_size (object_list) > 0)
				return;
		}
	}
	g_hash_table_remove (manager->priv->listened_dbus_names, dbus_owner);
	g_hash_table_remove (manager->priv->removed_dbus_names, dbus_owner);

	g_message ("Removed from listened DBUS names list");
	if (manager->priv->is_disposing &&
	        g_hash_table_size (manager->priv->listened_dbus_names) == 0) {
		g_message ("Manager disposed");
		manager->priv->disposed = TRUE;
		g_signal_emit (manager, signals [DISPOSED], 0);
	}

}

static void
ods_manager_session_list_add (OdsManager *manager, OdsSession *session,
                              OdsBluezCancellable *bluetooth_cancel_data,
                              const gchar *bluetooth_target_address,
                              const gchar *bluetooth_source_address,
                              const gint usb_interface_number,
                              const gchar *tty_dev,
                              const gchar *dbus_owner,
                              const gchar *dbus_path)
{
	OdsManagerSessionInfo *session_info;

	session_info = g_new0 (OdsManagerSessionInfo, 1);
	session_info->session = session;
	session_info->bluetooth_cancel_data = bluetooth_cancel_data;
	session_info->bluetooth_target_address = g_strdup (bluetooth_target_address);
	session_info->bluetooth_source_address = g_strdup (bluetooth_source_address);
	session_info->usb_interface_number = usb_interface_number;
	session_info->tty_dev = g_strdup (tty_dev);
	g_hash_table_insert (manager->priv->session_list, g_strdup (dbus_path),
	                     session_info);
	ods_manager_listened_names_add (manager, dbus_owner, dbus_path);
}

static void
ods_manager_server_list_add (OdsManager *manager, OdsServer *server,
                             const gchar *bluetooth_source_address,
                             gboolean require_pairing,
                             guint32 sdp_record_handle,
                             const gchar *tty_dev,
                             const gchar *dbus_owner,
                             const gchar *dbus_path)
{
	OdsManagerServerInfo *server_info;

	server_info = g_new0 (OdsManagerServerInfo, 1);
	server_info->server = server;
	server_info->bluetooth_source_address = g_strdup (bluetooth_source_address);
	server_info->require_pairing = require_pairing;
	server_info->sdp_record_handle = sdp_record_handle;
	server_info->tty_dev = g_strdup (tty_dev);
	g_hash_table_insert (manager->priv->server_list, g_strdup (dbus_path),
	                     server_info);
	ods_manager_listened_names_add (manager, dbus_owner, dbus_path);
}

static void
ods_manager_session_info_free (OdsManagerSessionInfo *session_info)
{
	g_free (session_info->bluetooth_target_address);
	g_free (session_info->bluetooth_source_address);
	g_free (session_info->tty_dev);
	g_free (session_info);
}

static void
ods_manager_server_info_free (OdsManagerServerInfo *server_info)
{
	g_free (server_info->bluetooth_source_address);
	g_free (server_info->tty_dev);
	g_free (server_info);
}

static void
ods_manager_session_list_remove (OdsManager *manager, OdsSession *session)
{
	gchar *session_object;
	gchar *owner;

	g_object_get (session, "dbus-path", &session_object, NULL);
	g_object_get (session, "owner", &owner, NULL);

	if (!manager->priv->is_disposing)
		g_hash_table_remove (manager->priv->session_list, session_object);
	ods_manager_listened_names_remove (manager, owner, session_object);

	g_free (session_object);
	g_free (owner);
}

static void
ods_manager_server_list_remove (OdsManager *manager, OdsServer *server)
{
	gchar *server_object;
	gchar *owner;

	g_object_get (server, "dbus-path", &server_object, NULL);
	g_object_get (server, "owner", &owner, NULL);

	if (!manager->priv->is_disposing)
		g_hash_table_remove (manager->priv->server_list, server_object);
	ods_manager_listened_names_remove (manager, owner, server_object);

	g_free (server_object);
	g_free (owner);
}

static void
session_closed_cb (OdsSession *session, OdsManager *manager)
{
	gchar *session_object;

	g_message ("session closed");
	g_object_get (session, "dbus-path", &session_object, NULL);
	ods_manager_session_list_remove (manager, session);
	g_signal_emit (manager, signals [SESSION_CLOSED], 0, session_object);

	g_free (session_object);
	g_object_unref (session);
}

static void
session_connect_result_cb (OdsSession *session,	const gchar *error_name,
                           const gchar *error_message, OdsManager *manager)
{
	gchar	*session_object;

	g_message ("session_connect_result_cb");
	g_object_get (session, "dbus-path", &session_object, NULL);
	if (!error_name)
		g_signal_emit (manager, signals [SESSION_CONNECTED], 0, session_object);
	else {
		g_signal_emit (manager, signals [SESSION_CONNECT_ERROR], 0, session_object,
		               error_name, error_message);
		session_closed_cb (session, manager);
	}
	g_signal_handlers_disconnect_by_func (session,
	                                      G_CALLBACK (session_connect_result_cb), manager);
	g_free (session_object);
}

static void
server_disposed_cb (OdsServer *server, OdsManager *manager)
{
	g_message ("server closed");
	/* Free everything */
	ods_manager_server_list_remove (manager, server);

	g_object_unref (server);
}

static void
server_closed_cb (OdsServer *server, OdsManager *manager)
{
	g_message ("disposing server");
	g_signal_connect (server, "disposed", G_CALLBACK (server_disposed_cb), manager);
	ods_server_dispose (server);
}

static void
server_started_cb (OdsServer *server, OdsManager *manager)
{
	OdsManagerServerInfo	*server_info;
	gchar					*server_object;
	gchar					*path;
	guint					service;
	ImagingSdpData			*imagingdata = NULL;
	struct statvfs			sfs;
	guint32					record_handle;
	gint 					protocol;
	/* Add service record to SDP database */
	g_object_get (server, "dbus-path", &server_object, NULL);
	g_object_get (server, "path", &path, NULL);
	g_object_get (server, "service", &service, NULL);
	g_object_get (server, "protocol", &protocol, NULL);
	g_message("server_started_cb,protocol is %d",protocol);
	server_info = g_hash_table_lookup (manager->priv->server_list, server_object);

	if (!server_info->bluetooth_source_address) {
		/* nothing to do for tty server */
		goto out;
	}

	if (service == ODS_SERVICE_BIP) {
		/* ods currently supports ImagePush and RemoteDisplay
		 * as Imaging Responder */
		imagingdata = g_new0 (ImagingSdpData, 1);
		imagingdata->supp_capabilities |= BIP_SUPP_CAP_GENERIC_IMAGING;
		imagingdata->supp_capabilities |= BIP_SUPP_CAP_DISPLAYING;
		imagingdata->supp_features |= BIP_SUPP_FEAT_IMAGE_PUSH;
		imagingdata->supp_features |= BIP_SUPP_FEAT_REMOTE_DISPLAY;
		imagingdata->supp_functions |= BIP_SUPP_FUNC_GET_CAPABILITIES;
		imagingdata->supp_functions |= BIP_SUPP_FUNC_PUT_IMAGE;
		imagingdata->supp_functions |= BIP_SUPP_FUNC_PUT_LINKED_ATTACHMENT;
		imagingdata->supp_functions |= BIP_SUPP_FUNC_PUT_LINKED_THUMBNAIL;
		imagingdata->supp_functions |= BIP_SUPP_FUNC_REMOTE_DISPLAY;
		if (statvfs (path, &sfs) == -1)
			imagingdata->data_capacity = 0;
		else
			imagingdata->data_capacity = (guint64)sfs.f_frsize * sfs.f_bfree;
	}
	record_handle = ods_bluez_add_service_record (
	                    server_info->bluetooth_source_address,
	                    service, imagingdata);
	if (record_handle == 0) {
		/* could not add SDP record */
		g_warning ("Could not add SDP record for server (%s), closing server",
		           server_object);
		/* stop server */
		g_signal_connect (server, "disposed", G_CALLBACK (server_disposed_cb), manager);
		g_object_run_dispose (G_OBJECT (server));
	} else {
		server_info->sdp_record_handle = record_handle;
	}

out:
	g_free (server_object);
	g_free (path);
	if (imagingdata)
		g_free (imagingdata);
}

static void
server_stopped_cb (OdsServer *server, OdsManager *manager)
{
	OdsManagerServerInfo	*server_info;
	gchar					*server_object;
	guint					service;

	g_message ("server stopped");
	g_object_get (server, "dbus-path", &server_object, NULL);
	g_object_get (server, "service", &service, NULL);

	/* Remove SDP record (Bluetooth specific) */
	server_info = g_hash_table_lookup (manager->priv->server_list, server_object);
	if (!server_info)
		goto out;

	if (server_info->sdp_record_handle &&
	        server_info->bluetooth_source_address) {
		ods_bluez_remove_service_record (server_info->bluetooth_source_address,
		                                 server_info->sdp_record_handle,service);
	}

out:
	g_free (server_object);
}

static void
session_cancelled_cb (OdsSession *session, OdsManager *manager)
{
	GError *error = NULL;

	g_message ("session cancelled");
	g_signal_connect (session, "disconnected",
	                  G_CALLBACK (session_closed_cb), manager);
	if (ods_session_disconnect_internal (session, &error) == -1) {
		/* shouldn't ever happen */
		g_clear_error (&error);
	}
}

static void
ods_manager_finalize_object (gpointer *object, OdsManager *manager)
{
	OdsManagerSessionInfo	*session_info;
	OdsManagerServerInfo	*server_info;

	/* Determine whether we have to close a session or a server */
	if ((session_info = g_hash_table_lookup (manager->priv->session_list,
	                    object))) {
		g_warning ("Finalizing session");
		ods_manager_session_finalize (NULL, session_info, manager);
	} else if ((server_info = g_hash_table_lookup (manager->priv->server_list,
	                          object))) {
		g_warning ("Finalizing server");
		ods_manager_server_finalize (NULL, server_info, manager);
	}
}

static void
dbus_name_owner_changed_cb (DBusGProxy *dbus_proxy, const gchar *name,
                            const gchar *old_owner, const gchar *new_owner,
                            OdsManager *manager)
{
	GHashTable	*object_list;
	GList		*object_list_dup;

	if (*new_owner != '\0')
		return;
	/* Lookup this name */
	object_list = g_hash_table_lookup (manager->priv->listened_dbus_names, name);
	if (object_list == NULL ||
	        (g_hash_table_lookup (manager->priv->removed_dbus_names, name) != NULL))
		return;
	g_warning ("DBUS NAME REMOVED: %s", name);
	/* insert into removed_dbus_names cause NameOwnerChanged signal
	 * might be received twice. Use manager as bogus value */
	g_hash_table_insert (manager->priv->removed_dbus_names, g_strdup (name), manager);

	/* Now we finalize all objects (sessions and servers) */
	object_list_dup = ods_hash_table_get_keys (object_list);
	g_list_foreach (object_list_dup, (GFunc) ods_manager_finalize_object, manager);
	g_list_free (object_list_dup);
}

static void
client_socket_connected_cb (gint fd, gint rfcomm_channel,
                            const ImagingSdpData *imagingdata, GError *error,
                            OdsManagerCreateSessionData *data)
{
	gchar					*session_object = NULL;
	gchar					*owner = NULL;
	OdsManagerSessionInfo	*session_info;
	gint					protocol = RFCOMM_OBEX;
	
	g_object_get (data->session, "dbus-path", &session_object, NULL);
	g_object_get (data->session, "owner", &owner, NULL);

	/* We need to reset cancel_data for this session so that it is
	 * properly finalized later on */
	session_info = g_hash_table_lookup (data->manager->priv->session_list,
	                                    session_object);
	g_assert (session_info);
	
	if (session_info->bluetooth_cancel_data)
		protocol = session_info->bluetooth_cancel_data->protocol;
	if (session_info->bluetooth_cancel_data)
		session_info->bluetooth_cancel_data = NULL;
	session_info->bluetooth_channel = rfcomm_channel;

	if (fd == -1) {
		gchar	*error_name;

		/* Could not connect, emit SessionConnectError */
		error_name = ods_error_get_dbus_name (error);
		g_signal_emit (data->manager, signals [SESSION_CONNECT_ERROR], 0,
		               session_object, error_name, error->message);
		g_free (error_name);

		/* Finalize session object*/
		session_closed_cb (data->session, data->manager);
		goto out;
	}
	if (imagingdata) {
		g_message ("Imaging SDP data:");
		g_message (">> capabilities: %" G_GUINT16_FORMAT, imagingdata->supp_capabilities);
		g_message (">> features: %" G_GUINT16_FORMAT, imagingdata->supp_features);
		g_message (">> functions: %" G_GUINT32_FORMAT, imagingdata->supp_functions);
		g_message (">> capacity: %" G_GUINT64_FORMAT, imagingdata->data_capacity);

		g_object_set (data->session, "imaging-sdp-data", imagingdata, NULL);
	}

	g_message ("Session created by: %s", owner);
	ods_session_set_protocol(session_info->session,protocol);
	/* Connect to the session objects signals. */
	g_signal_connect (data->session, "closed",
	                  G_CALLBACK (session_closed_cb), data->manager);
	g_signal_connect (data->session, "connect-result-internal",
	                  G_CALLBACK (session_connect_result_cb), data->manager);

	/* Set the connected socket as session fd.
	 * The session will automatically do OBEX Connect */
	g_object_set (data->session, "fd", fd, NULL);

out:
	g_free (owner);
	g_free (session_object);
	g_free (data);
}

static struct {
	const char	*name;
	uint16_t	class;
	gint		service;
} ods_services[] = {
	{ "pbap",	PBAP_SVCLASS_ID,				ODS_SERVICE_PBAP},
	{ "ftp",	OBEX_FILETRANS_SVCLASS_ID,		ODS_SERVICE_FTP	},
	{ "bip",	IMAGING_RESPONDER_SVCLASS_ID,	ODS_SERVICE_BIP },
	{ "opp",	OBEX_OBJPUSH_SVCLASS_ID,		ODS_SERVICE_OPP },
	{ }
};

static gboolean
pattern2service (const char *pattern, uint16_t *uuid, gint *service)
{
	int i;

	for (i = 0; ods_services[i].name; i++) {
		if (strcasecmp (ods_services[i].name, pattern) == 0) {
			*uuid = ods_services[i].class;
			*service = ods_services[i].service;
			return TRUE;
		}
	}

	return FALSE;
}

static gboolean
string2service (const char *string, uuid_t *uuid, gint *service)
{
	uint32_t data0, data4;
	uint16_t data1, data2, data3, data5;

	if (uuid && strlen(string) == 36 &&
	        string[8] == '-' &&
	        string[13] == '-' &&
	        string[18] == '-' &&
	        string[23] == '-' &&
	        sscanf(string, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
	               &data0, &data1, &data2, &data3, &data4, &data5) == 6) {
		uint8_t val[16];

		data0 = g_htonl(data0);
		data1 = g_htons(data1);
		data2 = g_htons(data2);
		data3 = g_htons(data3);
		data4 = g_htonl(data4);
		data5 = g_htons(data5);

		memcpy(&val[0], &data0, 4);
		memcpy(&val[4], &data1, 2);
		memcpy(&val[6], &data2, 2);
		memcpy(&val[8], &data3, 2);
		memcpy(&val[10], &data4, 4);
		memcpy(&val[14], &data5, 2);

		sdp_uuid128_create (uuid, val);
		/* we got UUID128, let's use generic GOEP service */
		*service = ODS_SERVICE_GOEP;

		return TRUE;
	} else {
		uint16_t class;

		/* got pattern specifying exactly which service to use */
		if (pattern2service (string, &class, service)) {
			if (uuid)
				sdp_uuid16_create (uuid, class);
			return TRUE;
		}
	}

	return FALSE;
}

static gint
tty_open (const gchar *tty_dev, GError **error)
{
	int fd, arg;
	glong flags;
	struct termios options;

	fd = open (tty_dev, O_RDWR | O_NOCTTY);
	if (fd < 0)
		goto failed;

	flags = fcntl (fd, F_GETFL);
	fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);

	tcgetattr (fd, &options);
	cfmakeraw (&options);
	options.c_oflag &= ~ONLCR;
	tcsetattr (fd, TCSANOW, &options);

	arg = fcntl (fd, F_GETFL);
	if (arg < 0)
		goto failed;

	arg |= O_NONBLOCK;
	if (fcntl (fd, F_SETFL, arg) < 0)
		goto failed;

	g_message ("TTY device %s opened", tty_dev);
	return fd;

failed:
	if (fd >= 0)
		close (fd);

	ods_error_err2gerror (errno, error);
	if (g_error_matches (*error, ODS_ERROR, ODS_ERROR_FAILED)) {
		/* replace "unknown errno" error with more readable one */
		g_debug ("Unknown err code: (%d)", errno);
		g_clear_error (error);
		g_set_error (error, ODS_ERROR, ODS_ERROR_FAILED,
		             "Could not open tty device");
	}
	return -errno;
}

static gboolean
create_bluetooth_session_full (OdsManager *manager,
                               const gchar *target_address,
                               const gchar *source_address,
                               const gchar *pattern,
                               const gchar *bip_feature,
                               DBusGMethodInvocation *context)
{
	GError		*error = NULL;
	gboolean	ret = TRUE;
	gboolean	valid;
	bdaddr_t	src;
	bdaddr_t	dst;
	uuid_t		uuid;
	gint		service;
	gchar		**parsed = NULL;
	OdsSession	*session;
	gchar		*sender;
	gchar		*session_object;
	gchar		*target_uuid = NULL;
	guint		imaging_feature = 0;
	OdsBluezCancellable	*cancel_data;
	g_message ("create_bluetooth_session_full");

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (ODS_IS_MANAGER (manager), FALSE);

	/* check target address validity */
	str2ba (target_address, &dst);
	/* can be only real address */
	valid = bachk (target_address) == 0 &&
	        bacmp (&dst, BDADDR_ANY) &&
	        bacmp (&dst, BDADDR_ALL);

	if (!valid) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid target Bluetooth address");
		dbus_g_method_return_error (context, error);
		ret = FALSE;
		goto out;
	}

	/* check address validity */
	str2ba (source_address, &src);
	/* can be real address or BDADDR_ANY */
	valid = bachk (source_address) == 0 &&
	        bacmp (&src, BDADDR_ALL);

	if (!valid) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid source Bluetooth address");
		dbus_g_method_return_error (context, error);
		ret = FALSE;
		goto out;
	}

	/* format of pattern at this point should be <service/uuid128>[:<channel>] */
	parsed = g_strsplit (pattern, ":", 2);

	/* convert pattern to service and bluetooth UUID */
	if (!string2service (parsed[0], &uuid, &service)) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid pattern");
		dbus_g_method_return_error (context, error);
		ret = FALSE;
		goto out;
	}

	/* determine target UUID according to service */
	switch (service) {
		case ODS_SERVICE_FTP:
			target_uuid = OBEX_FTP_UUID;
			break;
		case ODS_SERVICE_PBAP:
			target_uuid = OBEX_PBAP_UUID;
			break;
		case ODS_SERVICE_BIP:
			if (!g_ascii_strcasecmp (bip_feature, ODS_MANAGER_BIP_IMAGEPUSH_STR)) {
				target_uuid = OBEX_BIP_IPUSH_UUID;
				imaging_feature = BIP_SUPP_FEAT_IMAGE_PUSH;
			} else if (!g_ascii_strcasecmp (bip_feature, ODS_MANAGER_BIP_REMOTEDISPLAY_STR)) {
				target_uuid = OBEX_BIP_RD_UUID;
				imaging_feature = BIP_SUPP_FEAT_REMOTE_DISPLAY;
			} else {
				g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
				             "Unknown imaging feature");
				dbus_g_method_return_error (context, error);
				ret = FALSE;
				goto out;
			}
			break;
	}

	/* Create a session object */
	sender = dbus_g_method_get_sender (context);
	session = ods_session_new (-1, -1, service, sender, target_uuid);
	if (imaging_feature != 0)
		g_object_set (session, "imaging-feature", imaging_feature, NULL);
	g_object_get (session, "dbus-path", &session_object, NULL);

	/* connect Bluetooth transport (ods-bluez.c) */
	OdsManagerCreateSessionData *cb_data;/* data to pass to callback */

	cb_data = g_new0 (OdsManagerCreateSessionData, 1);
	cb_data->manager = manager;
	cb_data->session = session;

	/* start connecting socket for session */
	if (parsed[0])
		g_message ("Parsed[0]: %s", parsed[0]);
	if (parsed[1])
		g_message ("Parsed[1]: %s", parsed[1]);
	cancel_data = ods_bluez_get_client_socket (&dst, &src, &uuid,
	              imaging_feature,
	              (g_strv_length (parsed)>1 ? atoi (parsed[1]) : 0),
	              (OdsBluezFunc) client_socket_connected_cb,
	              cb_data);
	ods_manager_session_list_add (cb_data->manager, cb_data->session,
	                              cancel_data,
	                              target_address, source_address, -1, NULL,
	                              sender, session_object);

	if (!cancel_data) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_CONNECTION_ATTEMPT_FAILED,
		             "Service search failed (%s)", strerror (errno));
		client_socket_connected_cb (-1, -1, NULL, error, cb_data);
		/* SessionConnectError will be emitted immediately after session obj is returned */
	}

	/* Return session object now, SessionConnected will be emitted when
	 * session is fully connected */
	dbus_g_method_return (context, session_object);
	g_free (sender);
	g_free (session_object);

out:
	if (error)
		g_clear_error (&error);
	if (parsed)
		g_strfreev (parsed);
	return ret;
}

/**
 * ods_manager_create_bluetooth_session:
 * @manager: This class instance
 * @target_address: Bluetooth address of remote device to connect to
 * @source_address: Bluetooth address of local device (adapter)
 * @pattern: OBEX UUID (commonly "opp", "ftp", etc.)
 *
 * Creates and auto-connects Bluetooth session.
 *
 * Return value:
 **/
gboolean
ods_manager_create_bluetooth_session (OdsManager *manager,
                                      const gchar *target_address,
                                      const gchar *source_address,
                                      const gchar *pattern,
                                      DBusGMethodInvocation *context)
{
	g_message("ods_manager_create_bluetooth_session");
	return create_bluetooth_session_full (manager, target_address, source_address,
	                                      pattern, NULL, context);
}

/**
 * ods_manager_create_usb_session:
 * @manager: This class instance
 * @interface_number: USB OBEX interface number to connect to
 * @pattern: service used (commonly "ftp")
 *
 * Creates and auto-connects USB session.
 *
 * Return value:
 **/
gboolean
ods_manager_create_usb_session (OdsManager *manager,
                                const gint interface_number,
                                const gchar *pattern,
                                DBusGMethodInvocation *context)
{
	GError		*error = NULL;
	gboolean	ret = TRUE;
	OdsSession	*session;
	gint		service;
	gchar		*target_uuid = NULL;
	gchar		*sender;
	gchar		*session_object;

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (ODS_IS_MANAGER (manager), FALSE);

	if (interface_number < 0) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid USB interface number");
		dbus_g_method_return_error (context, error);
		ret = FALSE;
		goto out;
	}

	/* convert pattern to service and bluetooth UUID */
	if (!string2service (pattern, NULL, &service)) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid pattern");
		dbus_g_method_return_error (context, error);
		ret = FALSE;
		goto out;
	}

	/* FIXME detect unsuported services and error out */
	if (service == ODS_SERVICE_FTP)
		target_uuid = OBEX_FTP_UUID;

	/* Create a session object */
	sender = dbus_g_method_get_sender (context);
	session = ods_session_new (-1, -1, service, sender, target_uuid);
	g_object_get (session, "dbus-path", &session_object, NULL);

	ods_manager_session_list_add (manager, session,
	                              NULL, NULL, NULL, interface_number, NULL,
	                              sender, session_object);

	g_message ("Session created by: %s", sender);

	/* Connect to the session objects signals. */
	g_signal_connect (session, "closed",
	                  G_CALLBACK (session_closed_cb), manager);
	g_signal_connect (session, "connect-result-internal",
	                  G_CALLBACK (session_connect_result_cb), manager);
	/* Set USB interface number.
	 * The session will automatically do OBEX Connect */
	g_object_set (session, "usbintfnum", interface_number, NULL);

	/* Return session object now, SessionConnected will be emitted when
	 * session is fully connected */
	dbus_g_method_return (context, session_object);
	g_free (sender);
	g_free (session_object);

out:
	if (error)
		g_clear_error (&error);
	return ret;
}

static gboolean
connect_tty_session (gpointer data)
{
	OdsManagerCreateSessionData *cb_data = (OdsManagerCreateSessionData*) data;
	gint	fd;
	gchar	*session_object = NULL;
	GError	*error = NULL;
	gchar	*error_name = NULL;

	/* open tty device */
	fd = tty_open (cb_data->tty_dev, &error);
	if (fd < 0) {
		g_object_get (cb_data->session, "dbus-path", &session_object, NULL);

		/* Could not connect, emit SessionConnectError */
		error_name = ods_error_get_dbus_name (error);
		g_signal_emit (cb_data->manager, signals [SESSION_CONNECT_ERROR], 0,
		               session_object, error_name, error->message);
		/* Finalize session object*/
		session_closed_cb (cb_data->session, cb_data->manager);

		g_clear_error (&error);
		g_free (session_object);
		g_free (error_name);
	} else {
		/* Connect to the session objects signals. */
		g_signal_connect (cb_data->session, "closed",
		                  G_CALLBACK (session_closed_cb), cb_data->manager);
		g_signal_connect (cb_data->session, "connect-result-internal",
		                  G_CALLBACK (session_connect_result_cb), cb_data->manager);

		g_object_set (cb_data->session, "fd", fd, NULL);
	}

	g_free (cb_data->tty_dev);
	g_free (cb_data);
	return FALSE;
}

gboolean
ods_manager_create_tty_session (OdsManager *manager,
                                const gchar *tty_dev,
                                const gchar *pattern,
                                DBusGMethodInvocation *context)
{
	GError		*error = NULL;
	OdsSession	*session;
	gint		service;
	gchar		*target_uuid = NULL;
	gchar		*sender = NULL;
	gchar		*session_object = NULL;
	OdsManagerCreateSessionData *cb_data;

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (ODS_IS_MANAGER (manager), FALSE);

	/* convert pattern to service and bluetooth UUID */
	if (!string2service (pattern, NULL, &service)) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid pattern");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);

		return FALSE;
	}

	/* FIXME detect unsuported services and error out */
	if (service == ODS_SERVICE_FTP)
		target_uuid = OBEX_FTP_UUID;

	/* Create a session object */
	sender = dbus_g_method_get_sender (context);
	session = ods_session_new (-1, -1, service, sender, target_uuid);
	g_object_get (session, "dbus-path", &session_object, NULL);

	ods_manager_session_list_add (manager, session,
	                              NULL, NULL, NULL, -1, tty_dev,
	                              sender, session_object);
	g_message ("Session created by: %s", sender);


	/* connect will happen later in connect_tty_session */
	cb_data = g_new0 (OdsManagerCreateSessionData, 1);
	cb_data->manager = manager;
	cb_data->session = session;
	cb_data->tty_dev = g_strdup (tty_dev);
	g_idle_add (connect_tty_session, cb_data);

	/* Return session object now, SessionConnected will be emitted when
	 * session is fully connected */
	dbus_g_method_return (context, session_object);

	g_free (sender);
	g_free (session_object);
	return TRUE;
}

/**
 * ods_manager_get_usb_interfaces_num:
 * @manager: This class instance
 *
 * Returns number of currently available USB OBEX interfaces
 *
 * Return value:
 **/
guint
ods_manager_get_usb_interfaces_num (OdsManager *manager)
{
#ifdef USE_USB
	GList *list;
	guint num_interfaces;

	list = ods_usbobex_find_interfaces ();
	num_interfaces = g_list_length (list);
	ods_usbobex_free_interfaces (list);

	return num_interfaces;
#else
	return 0;
#endif /* USE_USB */
}

/**
 * ods_manager_get_usb_interfaces_info:
 * @manager: This class instance
 * @interface_number: the number of interface to return information about
 *
 * Returns information about a specific USB USB OBEX interface
 *
 * Return value:
 **/
GHashTable *
ods_manager_get_usb_interface_info (OdsManager *manager, const gint interface_number)
{
#ifdef USE_USB
	ods_usb_info *item;
	GList *list;
#endif
	GHashTable *info;

	info = g_hash_table_new_full ((GHashFunc)g_str_hash, (GEqualFunc)g_str_equal, NULL, (GDestroyNotify) g_free);

#ifdef USE_USB
	list = ods_usbobex_find_interfaces();
	item = g_list_nth_data (list, interface_number);
	if (item == NULL) {
		g_warning("No such USB interface, requested interface %d info", interface_number);
		return info;
	}

	g_message ("item->path %s", item->path);

	g_hash_table_insert (info, "Manufacturer",
	                     g_strdup (item->manufacturer));
	g_hash_table_insert (info, "Product",
	                     g_strdup (item->product));
	g_hash_table_insert (info, "Serial",
	                     g_strdup (item->serial));
	g_hash_table_insert (info, "Configuration",
	                     g_strdup (item->configuration));
	g_hash_table_insert (info, "ControlInterface",
	                     g_strdup (item->control_interface));
	g_hash_table_insert (info, "DataInterfaceIdle",
	                     g_strdup (item->data_interface_idle));
	g_hash_table_insert (info, "DataInterfaceActive",
	                     g_strdup (item->data_interface_active));
	g_hash_table_insert (info, "Path",
	                     g_strdup (item->path));

	ods_usbobex_free_interfaces (list);
#endif /* USE_USB */

	return info;
}

gboolean
ods_manager_create_bluetooth_imaging_session (OdsManager *manager,
        const gchar *target_address,
        const gchar *source_address,
        const gchar *bip_feature,
        DBusGMethodInvocation *context)
{
	gchar		**parsed;
	gchar		*pattern;
	gboolean	ret;

	parsed = g_strsplit (bip_feature, ":", 2);
	if (g_strv_length (parsed)>1)
		pattern = g_strdup_printf (ODS_MANAGER_BIP_STR ":%s", parsed[1]);
	else
		pattern = g_strdup (ODS_MANAGER_BIP_STR);

	ret = create_bluetooth_session_full (manager, target_address, source_address,
	                                     pattern, parsed[0], context);

	g_strfreev (parsed);
	g_free (pattern);
	return ret;
}

static gboolean
cancel_session_connect (OdsManager *manager,
                        OdsManagerSessionInfo *session_info)
{
	if (session_info->bluetooth_cancel_data) {
		ods_bluez_cancel_get_client_socket (session_info->bluetooth_cancel_data);
		return TRUE;
	}
	/* for future reference: Check for other transports cancellables */
	return FALSE;
}

gboolean
ods_manager_cancel_session_connect (OdsManager *manager,
                                    const gchar *session_object)
{
	OdsManagerSessionInfo	*session_info;

	session_info = g_hash_table_lookup (manager->priv->session_list, session_object);
	if (!session_info)
		return FALSE;
	return cancel_session_connect (manager, session_info);
}

gboolean
ods_manager_create_bluetooth_server (OdsManager *manager,
                                     const gchar *source_address,
                                     const gchar *pattern,
                                     gboolean require_pairing,                            
                                     gboolean obex_over_l2cap,
                                     DBusGMethodInvocation *context)
{
	GError		*error = NULL;
	gboolean	valid;
	bdaddr_t	bd_address;
	gint		service;
	guint8		channel;
	guint16		psm = 0;
	gint		fd;
	gint		sockopt;
	OdsServer	*server;
	gchar		*sender;
	gchar		*server_object;

	g_message ("ods_manager_create_bluetooth_server");
	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (ODS_IS_MANAGER (manager), FALSE);

	/* check address validity */
	str2ba (source_address, &bd_address);
	/* can be real address or BDADDR_ANY */
	valid = bachk (source_address) == 0 &&
	        bacmp (&bd_address, BDADDR_ALL);

	if (!valid) {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid Bluetooth address");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}

	/* check pattern validity (has to be supported/known service */
	if (!g_ascii_strcasecmp (pattern, ODS_MANAGER_FTP_STR)) {
		service = ODS_SERVICE_FTP;
		channel = ODS_FTP_RFCOMM_CHANNEL;
		psm = ODS_FTP_L2CAP_PSM;
	} else if (!g_ascii_strcasecmp (pattern, ODS_MANAGER_OPP_STR)) {
		service = ODS_SERVICE_OPP;
		channel = ODS_OPP_RFCOMM_CHANNEL;
		psm = ODS_OPP_L2CAP_PSM;
	} else if (!g_ascii_strcasecmp (pattern, ODS_MANAGER_PBAP_STR)) {
		service = ODS_SERVICE_PBAP;
		channel = ODS_PBAP_RFCOMM_CHANNEL;
		psm = ODS_PBAP_L2CAP_PSM;
	} else if (!g_ascii_strcasecmp (pattern, ODS_MANAGER_BIP_STR)) {
		service = ODS_SERVICE_BIP;
		channel = ODS_BIP_RFCOMM_CHANNEL;
		psm = ODS_BIP_L2CAP_PSM;
	} else {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid pattern");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}

	g_message ("create server socket ,service is %d ,obex_over_l2cap is %d",service,obex_over_l2cap);
	if(!obex_over_l2cap){
		/* create server socket */
		/*first create rfcomm socket*/
		fd = ods_bluez_get_server_socket (source_address, channel,RFCOMM_OBEX);
		if (fd == -1) {
			/* could not create server socket */
			g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
			             "Could not create server socket");
			dbus_g_method_return_error (context, error);
			g_clear_error (&error);
			return FALSE;
		}
		g_message ("server socket rfcomm created");

		/* require_pairing */
		if (require_pairing) {
			sockopt = RFCOMM_LM_AUTH | RFCOMM_LM_ENCRYPT;
			if (setsockopt (fd, SOL_RFCOMM, RFCOMM_LM, &sockopt, sizeof (sockopt)) < 0) {
				g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
				             "Setting RFCOMM link mode failed");
				dbus_g_method_return_error (context, error);
				g_clear_error (&error);
				return FALSE;
			}
		}
		
		/* create server object and return it's object path */
		sender = dbus_g_method_get_sender (context);
		g_message ("Server created by: %s", sender);
		server = ods_server_new (fd, service, sender,RFCOMM_OBEX);
	}
	else{
		
		/*create l2cap socket*/
		fd = ods_bluez_get_server_socket (source_address, psm,L2CAP_OBEX);
		if (fd == -1) {
			/* could not create server socket */
			g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
						 "Could not create server socket");
			dbus_g_method_return_error (context, error);
			g_clear_error (&error);
			return FALSE;
		}
		g_message ("server socket l2cap created");
		/* require_pairing */
		if (require_pairing) {
			sockopt = L2CAP_LM_AUTH | L2CAP_LM_ENCRYPT;
			if (setsockopt (fd,SOL_L2CAP, L2CAP_LM,&sockopt, sizeof (sockopt)) < 0) {
				g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
							 "Setting L2CAP link mode failed");
				dbus_g_method_return_error (context, error);
				g_clear_error (&error);
				return FALSE;
			}
		}
		
		/* create server object and return it's object path */
		sender = dbus_g_method_get_sender (context);
		g_message ("Server created by: %s", sender);
		server = ods_server_new (fd, service, sender,L2CAP_OBEX);

	}
		

	/* add server to server list */
	g_object_get (server, "dbus-path", &server_object, NULL);
	ods_manager_server_list_add (manager, server, source_address, require_pairing,
	                             0, NULL, sender, server_object);

	/* deal with signals */
	g_signal_connect (server, "started", G_CALLBACK (server_started_cb), manager);
	g_signal_connect (server, "stopped", G_CALLBACK (server_stopped_cb), manager);
	g_signal_connect (server, "closed", G_CALLBACK (server_closed_cb), manager);

	/* return server object path */
	dbus_g_method_return (context, server_object);

	g_free (sender);
	g_free (server_object);
	return TRUE;
}

gboolean
ods_manager_create_tty_server (OdsManager *manager,
                               const gchar *tty_dev,
                               const gchar *pattern,
                               DBusGMethodInvocation *context)
{
	GError		*error = NULL;
	gint		service;
	gint		fd;
	OdsServer	*server;
	gchar		*sender;
	gchar		*server_object;

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (ODS_IS_MANAGER (manager), FALSE);

	/* check pattern validity (has to be supported/known service */
	if (!g_ascii_strcasecmp (pattern, ODS_MANAGER_FTP_STR))
		service = ODS_SERVICE_FTP;
	else if (!g_ascii_strcasecmp (pattern, ODS_MANAGER_OPP_STR))
		service = ODS_SERVICE_OPP;
	else if (!g_ascii_strcasecmp (pattern, ODS_MANAGER_PBAP_STR))
		service = ODS_SERVICE_PBAP;
	else if (!g_ascii_strcasecmp (pattern, ODS_MANAGER_BIP_STR))
		service = ODS_SERVICE_BIP;
	else {
		g_set_error (&error, ODS_ERROR,	ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid pattern");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}

	/* open tty device */
	fd = tty_open (tty_dev, &error);
	if (fd < 0) {
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}

	/* create server object and return it's object path */
	sender = dbus_g_method_get_sender (context);
	g_message ("Server created by: %s", sender);
	server = ods_server_new (fd, service, sender,RFCOMM_OBEX);
	g_object_set (server, "tty-dev", tty_dev, NULL);

	/* add server to server list */
	g_object_get (server, "dbus-path", &server_object, NULL);
	ods_manager_server_list_add (manager, server, NULL, FALSE,	0, tty_dev,
	                             sender, server_object);

	/* deal with signals */
	g_signal_connect (server, "started", G_CALLBACK (server_started_cb), manager);
	g_signal_connect (server, "stopped", G_CALLBACK (server_stopped_cb), manager);
	g_signal_connect (server, "closed", G_CALLBACK (server_closed_cb), manager);

	/* return server object path */
	dbus_g_method_return (context, server_object);

	g_free (sender);
	g_free (server_object);
	return TRUE;
}

GHashTable *
ods_manager_get_session_info (OdsManager *manager, gchar *session_object)
{
	GHashTable *info;
	OdsManagerSessionInfo	*session_info;

	info = g_hash_table_new ((GHashFunc)g_str_hash, (GEqualFunc)g_str_equal);
	session_info = g_hash_table_lookup (manager->priv->session_list, session_object);
	if (session_info) {
		if (session_info->bluetooth_target_address) {
			g_hash_table_insert (info, "BluetoothTargetAddress",
			                     g_strdup (session_info->bluetooth_target_address));
			g_hash_table_insert (info, "BluetoothSourceAddress",
			                     g_strdup (session_info->bluetooth_source_address));
			g_hash_table_insert (info, "BluetoothChannel",
			                     g_strdup_printf ("%d", session_info->bluetooth_channel));
		}
		if (session_info->usb_interface_number > 0) {
			g_hash_table_insert (info, "UsbInterfaceNumber",
			                     g_strdup_printf ("%d", session_info->usb_interface_number));
		}
		if (session_info->tty_dev) {
			g_hash_table_insert (info, "TTYDevice",
			                     g_strdup (session_info->tty_dev));
		}
	}
	return info;
}

GHashTable *
ods_manager_get_server_info (OdsManager *manager, gchar *server_object)
{
	GHashTable *info;
	OdsManagerServerInfo	*server_info;

	info = g_hash_table_new ((GHashFunc)g_str_hash, (GEqualFunc)g_str_equal);
	server_info = g_hash_table_lookup (manager->priv->server_list, server_object);
	if (server_info) {
		if (server_info->bluetooth_source_address) {
			g_hash_table_insert (info, "BluetoothSourceAddress",
			                     g_strdup (server_info->bluetooth_source_address));
			g_hash_table_insert (info, "RequirePairing",
			                     g_strdup (server_info->require_pairing ? "True": "False"));
		}
		if (server_info->tty_dev) {
			g_hash_table_insert (info, "TTYDevice",
			                     g_strdup (server_info->tty_dev));
		}
	}
	return info;
}

gchar**
ods_manager_get_session_list (OdsManager *manager)
{
	return ods_hash_table_keys2strv (manager->priv->session_list);
}

gchar**
ods_manager_get_server_list (OdsManager *manager)
{
	return ods_hash_table_keys2strv (manager->priv->server_list);
}

gchar*
ods_manager_get_version (OdsManager *manager)
{
	return g_strdup_printf ("%s:%d", PACKAGE_VERSION, ODS_API_VERSION);
}

/**
 * ods_manager_class_init:
 * @klass: The OdsManagerClass
 **/
static void
ods_manager_class_init (OdsManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = ods_manager_finalize;

	signals [SESSION_CONNECTED] =
	    g_signal_new ("session-connected",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsManagerClass, session_connected),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__STRING,
	                  G_TYPE_NONE, 1, DBUS_TYPE_G_OBJECT_PATH);

	signals [SESSION_CLOSED] =
	    g_signal_new ("session-closed",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsManagerClass, session_closed),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__STRING,
	                  G_TYPE_NONE, 1, DBUS_TYPE_G_OBJECT_PATH);

	signals [SESSION_CONNECT_ERROR] =
	    g_signal_new ("session-connect-error",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsManagerClass, session_connect_error),
	                  NULL,
	                  NULL,
	                  ods_marshal_VOID__STRING_STRING_STRING,
	                  G_TYPE_NONE, 3, DBUS_TYPE_G_OBJECT_PATH, G_TYPE_STRING, G_TYPE_STRING);

	signals [DISPOSED] =
	    g_signal_new ("disposed",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsManagerClass, disposed),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

	g_type_class_add_private (klass, sizeof (OdsManagerPrivate));

	GError *error = NULL;

	/* Init the DBus connection, per-klass */
	klass->connection = dbus_g_bus_get (ODS_DBUS_BUS, &error);
	if (klass->connection == NULL) {
		g_warning("Unable to connect to dbus: %s", error->message);
		g_clear_error (&error);
		return;
	}

	/* &dbus_glib_ods_manager_object_info is provided in the
	 * dbus/ods-manager-dbus-glue.h file */
	dbus_g_object_type_install_info (ODS_TYPE_MANAGER, &dbus_glib_ods_manager_object_info);
	/* also register global error domain */
	dbus_g_error_domain_register (ODS_ERROR, ODS_ERROR_DBUS_INTERFACE, ODS_TYPE_ERROR);

}

/**
 * ods_manager_init:
 * @manager: This class instance
 **/
static void
ods_manager_init (OdsManager *manager)
{
	OdsManagerClass *klass = ODS_MANAGER_GET_CLASS (manager);
	manager->priv = ODS_MANAGER_GET_PRIVATE (manager);

	manager->priv->session_list = g_hash_table_new_full (g_str_hash, g_str_equal,
	                              g_free, (GDestroyNotify) ods_manager_session_info_free);
	manager->priv->server_list = g_hash_table_new_full (g_str_hash, g_str_equal,
	                             g_free, (GDestroyNotify) ods_manager_server_info_free);
	manager->priv->initialized = TRUE;/* For future use */

	manager->priv->dbus_proxy = dbus_g_proxy_new_for_name (klass->connection,
	                            DBUS_SERVICE_DBUS,
	                            DBUS_PATH_DBUS,
	                            DBUS_INTERFACE_DBUS);
	dbus_g_proxy_add_signal (manager->priv->dbus_proxy, "NameOwnerChanged",
	                         G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (manager->priv->dbus_proxy, "NameOwnerChanged",
	                             G_CALLBACK (dbus_name_owner_changed_cb),
	                             manager, NULL);

	manager->priv->listened_dbus_names = g_hash_table_new_full (g_str_hash,
	                                     g_str_equal, g_free, (GDestroyNotify) g_hash_table_unref);
	manager->priv->removed_dbus_names = g_hash_table_new_full (g_str_hash,
	                                    g_str_equal, g_free, NULL);

	dbus_g_connection_register_g_object (klass->connection,
	                                     ODS_MANAGER_DBUS_PATH,
	                                     G_OBJECT (manager));
}

static gboolean
ods_manager_session_finalize (gpointer key, OdsManagerSessionInfo *session_info,
                              OdsManager *manager)
{
	g_message ("attempting to close session");

	/* If session is being connected, cancel */
	if (cancel_session_connect (manager, session_info))
		return TRUE;
	/* Finalize already connected session */
	g_signal_connect (session_info->session, "cancelled",
	                  G_CALLBACK (session_cancelled_cb), manager);
	ods_session_cancel_internal (session_info->session);
	/* Even if there was nothing to cancel, we will get
	 * CANCELLED signal and disconnection will happen in
	 * session_cancelled_cb */

	return TRUE;
}

static gboolean
ods_manager_server_finalize (gpointer key, OdsManagerServerInfo *server_info,
                             OdsManager *manager)
{
	OdsServer *server = server_info->server;

	/* STOPPED signal will not be emitted, call teh callback now */
	server_stopped_cb (server, manager);

	g_signal_connect (server, "disposed", G_CALLBACK (server_disposed_cb), manager);
	ods_server_dispose (server);

	return TRUE;
}

void
ods_manager_dispose (OdsManager	*manager)
{
	g_return_if_fail (manager != NULL);
	g_return_if_fail (ODS_IS_MANAGER (manager));

	g_return_if_fail (manager->priv != NULL);
	if (manager->priv->disposed)
		return;

	g_message ("Disposing manager");
	manager->priv->is_disposing = TRUE;
	/* check if there is nothing to dispose */
	if (g_hash_table_size (manager->priv->listened_dbus_names) == 0) {
		g_message ("Manager disposed at once");
		manager->priv->disposed = TRUE;
		g_signal_emit (manager, signals [DISPOSED], 0);
	} else {
		g_hash_table_foreach_remove (manager->priv->session_list,
		                             (GHRFunc) ods_manager_session_finalize, manager);
		g_hash_table_foreach_remove (manager->priv->server_list,
		                             (GHRFunc) ods_manager_server_finalize, manager);
	}
}

/**
 * ods_manager_finalize:
 * @object: The object to finalize
 *
 * Finalise the manager, by unref'ing all the depending modules.
 **/
static void
ods_manager_finalize (GObject *object)
{
	OdsManager	*manager;

	g_return_if_fail (object != NULL);
	g_return_if_fail (ODS_IS_MANAGER (object));

	manager = ODS_MANAGER (object);

	g_return_if_fail (manager->priv != NULL);
	g_return_if_fail (manager->priv->disposed);

	g_message ("Finalizing manager");
	ods_bluez_finalize();
	g_hash_table_unref (manager->priv->listened_dbus_names);
	g_hash_table_unref (manager->priv->session_list);
	g_hash_table_unref (manager->priv->server_list);
	g_object_unref (G_OBJECT (manager->priv->dbus_proxy));

	G_OBJECT_CLASS (ods_manager_parent_class)->finalize (object);
}

/**
 * ods_manager_new:
 *
 * Return value: a new OdsManager object.
 **/
OdsManager *
ods_manager_new (void)
{
	OdsManager *manager;
	manager = g_object_new (ODS_TYPE_MANAGER, NULL);
	return ODS_MANAGER (manager);
}

/**
 * ods_manager_is_initialized:
 * @manager: OdsManager instance
 *
 * Checks if object was initialized succesfully. Might not be initialized
 * if OdsBluez was not initialized successfully
 *
 * Return value: TRUE for success, FALSE otherwise.
 **/
gboolean
ods_manager_is_initialized (OdsManager *manager)
{
	return manager->priv->initialized;
}

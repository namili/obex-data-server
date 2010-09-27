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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include <glib.h>
#include <glib/gprintf.h>

#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "ods-common.h"
#include "ods-error.h"
#include "ods-marshal.h"
#include "ods-server.h"
#include "ods-server-dbus-glue.h"
#include "ods-server-session.h"


static GObject* ods_server_constructor (GType type, guint n_construct_params,
                                        GObjectConstructParam *construct_params);
static void     ods_server_finalize	(GObject		*object);
static void     ods_server_attach_callback(OdsServer* server);

#define ODS_SERVER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), ODS_TYPE_SERVER, OdsServerPrivate))

/* this is used for timed assignment of ServerSession fd */
#define SERVER_SESSION_INIT_TIMEOUT 250 /* timeout in milliseconds */
typedef struct OdsServerSessionCbData_ {
	gint				fd;
	OdsServerSession	*session;
} OdsServerSessionCbData;

/* this structure is used for ServerSession list */
typedef struct OdsServerSessionInfo_ {
	OdsServerSession	*session;
	/* Bluetooth specific */
	gchar				*bluetooth_address;
} OdsServerSessionInfo;

struct OdsServerPrivate {
	/* viariables used when disposing/stopping */
	gboolean				is_disposing;
	gboolean				is_stopping;
	guint					open_sessions;
	gboolean				socket_error;
	gboolean				disposed;
	/* constructor properties */
	gint					fd; /* rfcomm device */
	guint					service;
	gchar					*owner; /* D-Bus client, who initiated this server */
	/* additional options (set via SetOption) */
	guint					limit;
	gboolean				require_imaging_thumbnails;
	/* io channel */
	GIOChannel				*io_channel;
	guint					io_watch;
	/* other */
	gchar					*tty_dev;
	gchar					*dbus_path; /* D-Bus path for this object */
	gboolean				started; /* Whether server is started and accepts connections */
	gchar					*path; /* Server root path */
	gboolean				allow_write; /* Whether to allow changes in file system */
	gboolean				auto_accept;/* Whether incoming files should be auto-accepted */
	GHashTable				*session_list; /* Server client list */
	gint					protocol; /* rfcomm or l2cap*/
};

enum {
	STARTED,
	STOPPED,
	CLOSED,
	SESSION_CREATED,
	SESSION_REMOVED,
	ERROR_OCCURRED,
	DISPOSED,
	LAST_SIGNAL
};

#define OPT_REQ_IMG_THUMBNAILS	"RequireImagingThumbnails"
#define OPT_LIMIT				"Limit"

static guint	signals [LAST_SIGNAL] = { 0, };
/* for numbering servers */
static guint	iterator = 0;

G_DEFINE_TYPE (OdsServer, ods_server, G_TYPE_OBJECT)

static void
ods_server_session_list_add (OdsServer *server, OdsServerSession *session,
                             bdaddr_t *bdaddr,
                             const gchar *dbus_path)
{
	OdsServerSessionInfo	*session_info;
	bdaddr_t				bdaddr2;

	session_info = g_new0 (OdsServerSessionInfo, 1);
	session_info->session = session;
	if (bdaddr) {
		baswap (&bdaddr2, bdaddr);
		session_info->bluetooth_address = batostr (&bdaddr2);
		g_message ("Bluetooth address: %s", session_info->bluetooth_address);
	}
	g_hash_table_insert (server->priv->session_list, g_strdup (dbus_path),
	                     session_info);
}

static void
ods_server_session_info_free (OdsServerSessionInfo *session_info)
{
	g_free (session_info->bluetooth_address);
	g_free (session_info);
}

static void
server_session_disconnected_cb (OdsServerSession *server_session,
                                OdsServer *server)
{
	gchar *session_object = NULL;

	g_message ("server session closed");
	g_object_get (server_session, "dbus-path", &session_object, NULL);

	if (!server->priv->is_disposing && !server->priv->is_stopping)
		g_hash_table_remove (server->priv->session_list, session_object);
	else if(server->priv->open_sessions>0)
		server->priv->open_sessions--;

	g_signal_emit (server, signals [SESSION_REMOVED], 0, session_object);

	g_object_unref (server_session);
	g_free (session_object);
	if (server->priv->open_sessions == 0) {
		if (server->priv->is_disposing) {
			g_message ("Server disposed");
			server->priv->disposed = TRUE;
			g_signal_emit (server, signals [DISPOSED], 0);
		} else if (server->priv->is_stopping) {
			g_message ("Server stopped");
			server->priv->is_stopping = FALSE;
			server->priv->started = FALSE;
			g_signal_emit (server, signals [STOPPED], 0);
			if (server->priv->socket_error)
				g_signal_emit (server, signals [CLOSED], 0);
		} else if (server->priv->tty_dev) {
			/* client disconnected from the socket, time to start listening for
			 * a new connection (see connect_callback). */
			ods_server_attach_callback(server);
		}
	}
}

static void
server_session_cancelled_cb (OdsServerSession *server_session)
{
	g_message ("server session cancelled");
	ods_server_session_disconnect_internal (server_session);
}

static gboolean
server_session_cancel (OdsServerSession *server_session)
{
	ods_server_session_cancel_internal (server_session);
	return FALSE;
}

static gboolean
server_session_finalize (gpointer key, OdsServerSessionInfo *session_info,
                         OdsServer *server)
{
	g_message ("attempting to close server session");
	g_signal_connect (session_info->session, "cancelled",
	                  G_CALLBACK (server_session_cancelled_cb), NULL);
	g_idle_add ((GSourceFunc) server_session_cancel, session_info->session);
	/* Even if there was nothing to cancel, we will get
	 * CANCELLED signal and disconnection will happen in
	 * session_cancelled_cb */

	return TRUE;
}

static gboolean
server_session_fd_assign (OdsServerSessionCbData *data)
{
	OdsServerSession *session = data->session;

	g_object_set (session, "fd", data->fd, NULL);
	g_free (data);
	return FALSE;
}

static gboolean
connect_callback (GIOChannel *source, GIOCondition cond, gpointer data)
{
	int					cli_fd, srv_fd;
	socklen_t			size;
	struct sockaddr_rc	cli_addr;
	bdaddr_t			*bdaddr = NULL;
	OdsServer			*server;
	OdsServerSession	*session;
	gchar				*session_object;
	OdsServerSessionCbData *cb_data;
	GError				*error = NULL;
	gboolean			ret = TRUE;
	gint 				protocol;
	g_message ("Client connecting");
	server = ODS_SERVER (data);
	g_object_get (server, "protocol", &protocol, NULL);
	g_message("connect_callback,protocol is %d",protocol);

	srv_fd = g_io_channel_unix_get_fd (source);

	if (!(cond & G_IO_IN)) {
		g_warning ("Error on server socket");
		g_set_error (&error, ODS_ERROR, ODS_ERROR_LINK_ERROR, "Error on server socket");
		ret = FALSE;
		goto out;
	}

	if (server->priv->tty_dev) {
		/* A TTY file descriptor can't accept() connection, it is the
		 * connection. We start out listening on it in ods-server; as soon as we
		 * get some input, we "disconnect" the fd from the ods-server and hand
		 * it off to the ods-server-session. When the session terminates
		 * (SIGHUP, etc), server_session_disconnected_cb will re-connect it to
		 * the ods-server to start waiting for the next session. */

		if (!server->priv->started)
			return TRUE; /* ignore requests until server is started */
		ods_safe_gsource_remove (&(server->priv->io_watch));
		cli_fd = srv_fd;
	} else {
		size = sizeof (struct sockaddr_rc);
		cli_fd = accept (srv_fd, (struct sockaddr*) &cli_addr, &size);
		if (!server->priv->started) {
			shutdown (cli_fd, SHUT_RDWR);
			close (cli_fd);
			return TRUE; /* ignore requests until server is started */
		}
		if (server->priv->limit > 0 &&
		        g_hash_table_size (server->priv->session_list) == server->priv->limit) {
			g_message ("ServerSession limit reached (%d), refusing connection",
			           server->priv->limit);
			shutdown (cli_fd, SHUT_RDWR);
			close (cli_fd);
			return TRUE;
		}
		if (cli_fd < 0) {
			g_message ("Error while accepting connection: %s", g_strerror (errno));
			ods_error_err2gerror (errno, &error);
			/* Ignore this error since we can just continue listening */
			goto out;
		}
	}

	/* To avoid race condition when client application misses TransferStarted
	 * signal from ServerSession object, we emit SessionCreated signal now,
	 * but assign fd to ServerSession (and therefore start OBEX operations)
	 * only after a timeout */
	session = ods_server_session_new (-1, server->priv->service,
	                                  server->priv->path,
	                                  server->priv->allow_write,
	                                  server->priv->auto_accept,
	                                  server->priv->require_imaging_thumbnails,
	                                  server->priv->owner);
	ods_server_session_set_protocol (session, protocol);
	if (server->priv->tty_dev)
		g_object_set (session, "using-tty", TRUE, NULL);

	cb_data = g_new0 (OdsServerSessionCbData, 1);
	cb_data->fd = cli_fd;
	cb_data->session = session;
	g_timeout_add (SERVER_SESSION_INIT_TIMEOUT,
	               (GSourceFunc) server_session_fd_assign, cb_data);

	/* deal with signals */
	g_signal_connect (session, "disconnected",
	                  G_CALLBACK (server_session_disconnected_cb), server);
	g_object_get (session, "dbus-path", &session_object, NULL);
	g_signal_emit (server, signals [SESSION_CREATED], 0, session_object);

	if (!server->priv->tty_dev) {
		/* this is Bluetooth server */
		bdaddr = &(cli_addr.rc_bdaddr);
	}
	ods_server_session_list_add (server, session, bdaddr, session_object);

	g_free (session_object);

out:
	if (error) {
		gchar *error_name;
		/* Get D-Bus name for error */
		error_name = ods_error_get_dbus_name (error);
		/* emit ErrorOccurred signal */
		g_signal_emit (server, signals [ERROR_OCCURRED], 0,
		               error_name, error->message);
		g_free (error_name);
		g_clear_error (&error);
	}
	if (!ret) {
		/* disconnect server sessions, cause there was error on server socket */
		if (g_hash_table_size (server->priv->session_list) == 0) {
			server->priv->started = FALSE;
			g_signal_emit (server, signals [STOPPED], 0);
			g_signal_emit (server, signals [CLOSED], 0);
		} else {
			server->priv->socket_error = TRUE;
			server->priv->is_stopping = TRUE;
			g_hash_table_foreach_remove (server->priv->session_list,
			                             (GHRFunc) server_session_finalize, NULL);
			/* STOPPED and CLOSED signals will be emitted in server_session_disconnected_cb */
		}
		g_hash_table_unref (server->priv->session_list);
	}

	return ret;
}

static void
ods_server_set_property (GObject      *object,
                         guint         property_id,
                         const GValue *value,
                         GParamSpec   *pspec)
{
	OdsServer *self = (OdsServer *) object;

	switch (property_id) {
		case ODS_SERVER_FD:
			self->priv->fd = g_value_get_int (value);
			break;
		case ODS_SERVER_SERVICE:
			self->priv->service = g_value_get_int (value);
			break;
		case ODS_SERVER_OWNER:
			self->priv->owner = g_value_dup_string (value);
			break;
		case ODS_SERVER_TTY_DEV:
			self->priv->tty_dev = g_value_dup_string (value);
			break;
		case ODS_SERVER_PROTOCOL:
			self->priv->protocol = g_value_get_int (value);
			break;
		default:
			/* We don't have any other property... */
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
			break;
	}
}

static void
ods_server_get_property (GObject      *object,
                         guint         property_id,
                         GValue       *value,
                         GParamSpec   *pspec)
{
	OdsServer *self = (OdsServer *) object;

	switch (property_id) {
		case ODS_SERVER_FD:
			g_value_set_int (value, self->priv->fd);
			break;
		case ODS_SERVER_SERVICE:
			g_value_set_int (value, self->priv->service);
			break;
		case ODS_SERVER_OWNER:
			g_value_set_string (value, self->priv->owner);
			break;
		case ODS_SERVER_DBUS_PATH:
			g_value_set_string (value, self->priv->dbus_path);
			break;
		case ODS_SERVER_PATH:
			g_value_set_string (value, self->priv->path);
			break;
		case ODS_SERVER_TTY_DEV:
			g_value_set_string (value, self->priv->tty_dev);
			break;
		case ODS_SERVER_PROTOCOL:
			g_value_set_int (value, self->priv->protocol);
			break;
		default:
			/* We don't have any other property... */
			G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
			break;
	}
}

/**
 * ods_server_class_init:
 * @klass: The OdsServerClass
 **/
static void
ods_server_class_init (OdsServerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->constructor = ods_server_constructor;
	object_class->finalize = ods_server_finalize;

	object_class->set_property = ods_server_set_property;
	object_class->get_property = ods_server_get_property;

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_FD,
	                                 g_param_spec_int ("fd",
	                                                   "", "",
	                                                   0, G_MAXINT, /* min, max values */
	                                                   0 /* default value */,
	                                                   G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_SERVICE,
	                                 g_param_spec_int ("service",
	                                                   "", "",
	                                                   0, G_MAXINT, /* min, max values */
	                                                   0 /* default value */,
	                                                   G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_OWNER,
	                                 g_param_spec_string ("owner",
	                                                      "", "",
	                                                      "" /* default value */,
	                                                      G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_DBUS_PATH,
	                                 g_param_spec_string ("dbus-path",
	                                                      "", "",
	                                                      "" /* default value */,
	                                                      G_PARAM_READABLE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_PATH,
	                                 g_param_spec_string ("path",
	                                                      "", "",
	                                                      "" /* default value */,
	                                                      G_PARAM_READABLE));

	g_object_class_install_property (object_class,
	                                 ODS_SERVER_TTY_DEV,
	                                 g_param_spec_string ("tty-dev",
	                                                      "", "",
	                                                      "" /* default value */,
	                                                      G_PARAM_READWRITE));
	
	g_object_class_install_property (object_class,
	                                 ODS_SERVER_PROTOCOL,
	                                 g_param_spec_int ("protocol",
	                                                   "", "",
	                                                   RFCOMM_OBEX,L2CAP_OBEX, /* min, max values */
	                                                   RFCOMM_OBEX /* default value */,
	                                                   G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE));

	signals [STARTED] =
	    g_signal_new ("started",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerClass, started),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

	signals [STOPPED] =
	    g_signal_new ("stopped",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerClass, stopped),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

	signals [CLOSED] =
	    g_signal_new ("closed",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerClass, closed),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

	signals [SESSION_CREATED] =
	    g_signal_new ("session-created",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerClass, session_created),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__STRING,
	                  G_TYPE_NONE, 1, DBUS_TYPE_G_OBJECT_PATH);

	signals [SESSION_REMOVED] =
	    g_signal_new ("session-removed",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerClass, session_removed),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__STRING,
	                  G_TYPE_NONE, 1, DBUS_TYPE_G_OBJECT_PATH);

	signals [ERROR_OCCURRED] =
	    g_signal_new ("error-occurred",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerClass, error_occurred),
	                  NULL,
	                  NULL,
	                  ods_marshal_VOID__STRING_STRING,
	                  G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);

	signals [DISPOSED] =
	    g_signal_new ("disposed",
	                  G_TYPE_FROM_CLASS (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  G_STRUCT_OFFSET (OdsServerClass, disposed),
	                  NULL,
	                  NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);

	g_type_class_add_private (klass, sizeof (OdsServerPrivate));

	GError *error = NULL;

	/* Init the DBus connection, per-klass */
	klass->connection = dbus_g_bus_get (ODS_DBUS_BUS, &error);
	if (klass->connection == NULL) {
		g_warning("Unable to connect to dbus: %s", error->message);
		g_clear_error (&error);
		return;
	}

	/* &dbus_glib_ods_server_object_info is provided in the
	 * dbus/ods-server-dbus-glue.h file */
	dbus_g_object_type_install_info (ODS_TYPE_SERVER, &dbus_glib_ods_server_object_info);
}

/**
 * ods_server_init:
 * @server This class instance
 **/
static void
ods_server_init (OdsServer *server)
{
	OdsServerClass *klass = ODS_SERVER_GET_CLASS (server);
	server->priv = ODS_SERVER_GET_PRIVATE (server);

	server->priv->session_list = g_hash_table_new_full (g_str_hash, g_str_equal,
	                             g_free, (GDestroyNotify) ods_server_session_info_free);
	/* figure out DBus object path for this instance */
	server->priv->dbus_path = g_strdup_printf (ODS_SERVER_DBUS_PATH_PATTERN,
	                          iterator);
	iterator++;

	dbus_g_connection_register_g_object (klass->connection,
	                                     server->priv->dbus_path,
	                                     G_OBJECT (server));
}


/**
 * Common logic for ods_server_constructor and server_session_disconnected_cb:
 * hooks connect_callback to the server's io channel
 */
static void ods_server_attach_callback(OdsServer* server)
{
	server->priv->io_watch = g_io_add_watch(server->priv->io_channel,
	                                        G_IO_IN | G_IO_HUP | G_IO_ERR,
	                                        connect_callback, server);
}


static GObject*
ods_server_constructor (GType type, guint n_construct_params,
                        GObjectConstructParam *construct_params)
{
	GObject *object;
	OdsServer *server;


	object = G_OBJECT_CLASS (ods_server_parent_class)->constructor (type,
	         n_construct_params,
	         construct_params);

	server = ODS_SERVER (object);


	server->priv->io_channel = g_io_channel_unix_new (server->priv->fd);
	ods_server_attach_callback(server);

	return object;
}

/**
 * ods_server_finalize:
 * @object: The object to finalize
 *
 * Finalize the server
 **/
static void
ods_server_finalize (GObject *object)
{
	OdsServer *server;

	g_return_if_fail (object != NULL);
	g_return_if_fail (ODS_IS_SERVER (object));

	server = ODS_SERVER (object);

	g_return_if_fail (server->priv != NULL);
	g_return_if_fail (server->priv->disposed);

	g_hash_table_unref (server->priv->session_list);
	/* close server socket */
	ods_safe_gsource_remove (&(server->priv->io_watch));
	g_io_channel_shutdown (server->priv->io_channel, TRUE, NULL);
	g_io_channel_unref(server->priv->io_channel);
	close (server->priv->fd);
	/* free other private variables */
	g_free (server->priv->owner);
	g_free (server->priv->dbus_path);
	g_free (server->priv->path);
	g_free (server->priv->tty_dev);

	G_OBJECT_CLASS (ods_server_parent_class)->finalize (object);
}

/**
 * ods_server_new:
 *
 * Return value: a new OdsServer object.
 **/
OdsServer *
ods_server_new (gint fd, gint service, const gchar *owner,gint protocol)
{
	OdsServer *server;
	server = g_object_new (ODS_TYPE_SERVER,
	                       "fd", fd,
	                       "service", service,
	                       "owner", owner,
	                       "protocol",protocol,
	                       NULL);
	return ODS_SERVER (server);
}

gboolean
ods_server_start (OdsServer *server, const gchar *path, gboolean allow_write,
                  gboolean auto_accept, DBusGMethodInvocation *context)
{
	GError *error = NULL;

	/* Check caller */
	if (!ods_check_caller (context, server->priv->owner))
		return FALSE;
	/* check if started */
	if (server->priv->started) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_STARTED,
		             "Already started");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}
	if (server->priv->is_stopping || server->priv->is_disposing) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_FAILED,
		             "Currently stopping");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}
	/* make sure supplied path is valid */
	if (!g_file_test (path, G_FILE_TEST_IS_DIR)) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_INVALID_ARGUMENTS,
		             "Invalid path");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}

	g_free (server->priv->path);
	server->priv->path = g_strdup (path);
	server->priv->allow_write = allow_write;
	server->priv->auto_accept = auto_accept;
	g_warning ("Server path: %s", path);
	server->priv->started = TRUE;
	g_signal_emit (server, signals [STARTED], 0);
	dbus_g_method_return (context);
	return TRUE;
}

gboolean
ods_server_stop (OdsServer *server, DBusGMethodInvocation *context)
{
	GError *error = NULL;

	/* Check caller */
	if (!ods_check_caller (context, server->priv->owner))
		return FALSE;
	/* check if not started */
	if (!server->priv->started) {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_NOT_STARTED,
		             "Not started");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}
	/* disconnect server sessions */
	if (g_hash_table_size (server->priv->session_list) == 0) {
		server->priv->started = FALSE;
		g_signal_emit (server, signals [STOPPED], 0);
	} else {
		server->priv->is_stopping = TRUE;
		g_hash_table_foreach_remove (server->priv->session_list,
		                             (GHRFunc) server_session_finalize, NULL);
		/* STOPPED signal will be emitted in server_session_disconnected_cb */
	}
	g_hash_table_unref (server->priv->session_list);
	server->priv->session_list = g_hash_table_new_full (g_str_hash, g_str_equal,
	                             g_free, (GDestroyNotify) ods_server_session_info_free);

	dbus_g_method_return (context);
	return TRUE;
}

gboolean
ods_server_close (OdsServer *server, DBusGMethodInvocation *context)
{
	/* Check caller */
	if (!ods_check_caller (context, server->priv->owner))
		return FALSE;
	if (server->priv->started)
		g_signal_emit (server, signals [STOPPED], 0);
	g_signal_emit (server, signals [CLOSED], 0);
	/* server socket will be closed when this GObject is finalized */
	dbus_g_method_return (context);
	return TRUE;
}

/* Not exposed through DBUS, used internally */
void
ods_server_dispose (OdsServer *server)
{
	g_return_if_fail (server != NULL);
	g_return_if_fail (ODS_IS_SERVER (server));
	g_return_if_fail (server->priv != NULL);
	if (server->priv->disposed)
		return;

	g_message ("Disposing Server");
	server->priv->is_disposing = TRUE;
	/* check if there is nothing to dispose */
	if (g_hash_table_size (server->priv->session_list) == 0) {
		g_message ("Server disposed at once");
		server->priv->disposed = TRUE;
		g_signal_emit (server, signals [DISPOSED], 0);
	} else {
		/* disconnect server sessions */
		server->priv->open_sessions = g_hash_table_size (server->priv->session_list);
		g_hash_table_foreach_remove (server->priv->session_list,
		                             (GHRFunc) server_session_finalize, NULL);
		/* when session_list becomes empty in server_session_disconnected callback
		 * "disposed" signal will be emitted */
	}
}

gboolean
ods_server_is_started (OdsServer *server)
{
	return server->priv->started;
}

gboolean
ods_server_set_option (OdsServer *server, const gchar *name, GValue *value,
                       DBusGMethodInvocation *context)
{
	GError *error = NULL;

	/* Check caller */
	if (!ods_check_caller (context, server->priv->owner))
		return FALSE;
	if (!g_ascii_strncasecmp (name, OPT_REQ_IMG_THUMBNAILS, strlen (name))) {
		/* require-imaging-thumbnails */
		if (!G_VALUE_HOLDS_BOOLEAN (value)) {
			g_set_error (&error, ODS_ERROR, ODS_ERROR_INVALID_ARGUMENTS,
			             "Invalid value for require-imaging-thumbnails");
			goto out;
		}
		server->priv->require_imaging_thumbnails = g_value_get_boolean (value);
	} else if (!g_ascii_strncasecmp (name, OPT_LIMIT, strlen (name))) {
		/* limit */
		if (!G_VALUE_HOLDS_UINT (value)) {
			g_set_error (&error, ODS_ERROR, ODS_ERROR_INVALID_ARGUMENTS,
			             "Invalid value for limit");
			goto out;
		}
		server->priv->limit = g_value_get_uint (value);
	} else {
		g_set_error (&error, ODS_ERROR, ODS_ERROR_INVALID_ARGUMENTS,
		             "Unknown option");
		goto out;
	}

out:
	if (error) {
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return FALSE;
	}
	dbus_g_method_return (context);
	return TRUE;
}

GHashTable *
ods_server_get_server_session_info (OdsServer *server, gchar *session_object)
{
	GHashTable				*info;
	OdsServerSessionInfo	*session_info;

	info = g_hash_table_new ((GHashFunc)g_str_hash, (GEqualFunc)g_str_equal);
	session_info = g_hash_table_lookup (server->priv->session_list, session_object);
	if (session_info && session_info->bluetooth_address) {
		g_hash_table_insert (info, "BluetoothAddress",
		                     g_strdup (session_info->bluetooth_address));
	}
	return info;
}

gchar**
ods_server_get_server_session_list (OdsServer *server)
{
	return ods_hash_table_keys2strv (server->priv->session_list);
}

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

#ifndef __ODS_SERVER_H
#define __ODS_SERVER_H

#include <glib-object.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

#define	ODS_SERVER_DBUS_PATH_PATTERN		"/org/openobex/server%d"
#define	ODS_SERVER_DBUS_INTERFACE			"org.openobex.Server"


#define ODS_TYPE_SERVER	 (ods_server_get_type ())
#define ODS_SERVER(o)		 (G_TYPE_CHECK_INSTANCE_CAST ((o), ODS_TYPE_SERVER, OdsServer))
#define ODS_SERVER_CLASS(k)	 (G_TYPE_CHECK_CLASS_CAST((k), ODS_TYPE_SERVER, OdsServerClass))
#define ODS_IS_SERVER(o)	 (G_TYPE_CHECK_INSTANCE_TYPE ((o), ODS_TYPE_SERVER))
#define ODS_IS_SERVER_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), ODS_TYPE_SERVER))
#define ODS_SERVER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), ODS_TYPE_SERVER, OdsServerClass))

enum {
  ODS_SERVER_FD = 1,
  ODS_SERVER_SERVICE,
  ODS_SERVER_OWNER,
  ODS_SERVER_DBUS_PATH,
  ODS_SERVER_PATH,
  ODS_SERVER_TTY_DEV
};

typedef struct OdsServerPrivate OdsServerPrivate;

typedef struct
{
	 GObject		 parent;
	 OdsServerPrivate	*priv;
} OdsServer;

typedef struct
{
	GObjectClass	parent_class;
	void		(* started)				(OdsServer	*server);
	void		(* stopped)				(OdsServer	*server);
	void		(* closed)				(OdsServer	*server);
	void		(* session_created)		(OdsServer	*server,
							 				const gchar *session_object);
	void		(* session_removed)		(OdsServer	*server,
							 				const gchar *session_object);
	void		(* error_occurred)		(OdsServer *server,
											const gchar *error_name,
											const gchar *error_message);
	void		(* disposed)			(OdsServer	*server);
	DBusGConnection *connection;
} OdsServerClass;


GType		 ods_server_get_type		(void);
OdsServer	*ods_server_new				(gint fd,
											gint service,
											const gchar *owner);
gboolean	 ods_server_start			(OdsServer *server,
											const gchar *path,
											gboolean allow_write,
											gboolean auto_accept,
											DBusGMethodInvocation *context);
gboolean	 ods_server_stop			(OdsServer *server,
											DBusGMethodInvocation *context);
gboolean	 ods_server_close			(OdsServer *server,
											DBusGMethodInvocation *context);
void		 ods_server_dispose			(OdsServer *server);
gboolean	 ods_server_is_started		(OdsServer *server);
gboolean	 ods_server_set_option		(OdsServer *server,
											const gchar *name,
											GValue *value,
											DBusGMethodInvocation *context);
GHashTable	*ods_server_get_server_session_info (OdsServer *server, gchar *session_object);
gchar		**ods_server_get_server_session_list (OdsServer *server);

G_END_DECLS

#endif /* __ODS_SERVER_H */


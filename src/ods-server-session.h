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

#ifndef __ODS_SERVER_SESSION_H
#define __ODS_SERVER_SESSION_H

#include <glib-object.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

#define ODS_TYPE_SERVER_SESSION			(ods_server_session_get_type ())
#define ODS_SERVER_SESSION(o)			(G_TYPE_CHECK_INSTANCE_CAST ((o), ODS_TYPE_SERVER_SESSION, OdsServerSession))
#define ODS_SERVER_SESSION_CLASS(k)		(G_TYPE_CHECK_CLASS_CAST((k), ODS_TYPE_SERVER_SESSION, OdsServerSessionClass))
#define ODS_IS_SERVER_SESSION(o)		(G_TYPE_CHECK_INSTANCE_TYPE ((o), ODS_TYPE_SERVER_SESSION))
#define ODS_IS_SERVER_SESSION_CLASS(k)	(G_TYPE_CHECK_CLASS_TYPE ((k), ODS_TYPE_SERVER_SESSION))
#define ODS_SERVER_SESSION_GET_CLASS(o)	(G_TYPE_INSTANCE_GET_CLASS ((o), ODS_TYPE_SERVER_SESSION, OdsServerSessionClass))

enum {
  ODS_SERVER_SESSION_FD = 1,
  ODS_SERVER_SESSION_SERVICE,
  ODS_SERVER_SESSION_PATH,
  ODS_SERVER_SESSION_ALLOW_WRITE,
  ODS_SERVER_SESSION_AUTO_ACCEPT,
  ODS_SERVER_SESSION_REQUIRE_IMAGING_THUMBNAILS,
  ODS_SERVER_SESSION_USING_TTY,
  ODS_SERVER_SESSION_OWNER,
  ODS_SERVER_SESSION_DBUS_PATH
};

typedef struct OdsServerSessionPrivate OdsServerSessionPrivate;

typedef struct
{
	 GObject		 			parent;
	 OdsServerSessionPrivate	*priv;
} OdsServerSession;

typedef struct
{
	GObjectClass	parent_class;
	void		(* cancelled)			(OdsServerSession *server_session);
	void		(* disconnected)		(OdsServerSession *server_session);
	void		(* transfer_started)	(OdsServerSession *server_session,
											const gchar *filename,
											const gchar *local_path,
											guint64 total_bytes);
	void		(* transfer_progress)	(OdsServerSession *server_session,
											guint64 bytes_transferred);
	void		(* transfer_completed)	(OdsServerSession *server_session);
	void		(* error_occurred)		(OdsServerSession *server_session,
											const gchar *error_name,
											const gchar *error_message);
	void		(* remote_display_requested) (OdsServerSession *server_session,
											const gchar *filename);
	DBusGConnection *connection;
} OdsServerSessionClass;


GType				 ods_server_session_get_type	(void);
OdsServerSession	*ods_server_session_new			(gint fd,
														gint service,
														const gchar *path,
														gboolean allow_write,
														gboolean auto_accept,
														gboolean require_imaging_thumbnails,
														const gchar *owner);
gboolean	 		 ods_server_session_accept		(OdsServerSession *server_session,
														DBusGMethodInvocation *context);
gboolean	 		 ods_server_session_reject		(OdsServerSession *server_session,
														DBusGMethodInvocation *context);
void				 ods_server_session_disconnect_internal (OdsServerSession *server_session);
gboolean			 ods_server_session_disconnect	(OdsServerSession *server_session,
														DBusGMethodInvocation *context);
GHashTable			*ods_server_session_get_transfer_info	(OdsServerSession *server_session);
gboolean			 ods_server_session_cancel_internal (OdsServerSession *server_session);
gboolean			 ods_server_session_cancel		(OdsServerSession *server_session,
														DBusGMethodInvocation *context);

G_END_DECLS

#endif /* __ODS_SERVER_SESSION_H */


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

#ifndef __ODS_SESSION_H
#define __ODS_SESSION_H

#include <glib-object.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

#define ODS_TYPE_SESSION	 (ods_session_get_type ())
#define ODS_SESSION(o)		 (G_TYPE_CHECK_INSTANCE_CAST ((o), ODS_TYPE_SESSION, OdsSession))
#define ODS_SESSION_CLASS(k)	 (G_TYPE_CHECK_CLASS_CAST((k), ODS_TYPE_SESSION, OdsSessionClass))
#define ODS_IS_SESSION(o)	 (G_TYPE_CHECK_INSTANCE_TYPE ((o), ODS_TYPE_SESSION))
#define ODS_IS_SESSION_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), ODS_TYPE_SESSION))
#define ODS_SESSION_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), ODS_TYPE_SESSION, OdsSessionClass))

enum {
  ODS_SESSION_FD = 1,
  ODS_SESSION_SERVICE,
  ODS_SESSION_OWNER,
  ODS_SESSION_DBUS_PATH,
  ODS_SESSION_IMAGING_FEATURE,
  ODS_SESSION_IMAGING_SDP_DATA,
  ODS_SESSION_TARGET_UUID,
  ODS_SESSION_USBINTFNUM
};

typedef struct OdsSessionPrivate OdsSessionPrivate;

typedef struct
{
	 GObject		 parent;
	 OdsSessionPrivate	*priv;
} OdsSession;

typedef struct
{
	GObjectClass	parent_class;
	void		(* cancelled)			(OdsSession	*session);
	void		(* connect_result_internal)	(OdsSession	*session,
											const gchar *error_name,
											const gchar *error_message);
	void		(* disconnected)		(OdsSession *session);
	void		(* closed)				(OdsSession *session);
	void		(* transfer_started)	(OdsSession *session,
											const gchar *filename,
											const gchar *local_path,
											guint64 total_bytes);
	void		(* transfer_progress)	(OdsSession *session,
											guint64 bytes_transferred);
	void		(* transfer_completed)	(OdsSession *session);
	void		(* error_occurred)		(OdsSession *session,
											const gchar *error_name,
											const gchar *error_message);
	void		(* image_handle_received)(OdsSession *session,
											const gchar *image_handle,
											gboolean thumbnail_requested);
	DBusGConnection *connection;
} OdsSessionClass;


GType		 ods_session_get_type		  				(void);
OdsSession	*ods_session_new							(gint fd,
															gint usb_interface_number,
															gint service,
															const gchar *owner,
															const gchar *target_uuid);
gint		 ods_session_disconnect_internal			(OdsSession *session,
															GError **error);
gboolean	 ods_session_disconnect						(OdsSession *session,
															DBusGMethodInvocation *context);
gboolean	 ods_session_close							(OdsSession *session,
															DBusGMethodInvocation *context);
gboolean	 ods_session_change_current_folder			(OdsSession *session,
															const gchar *path,
															DBusGMethodInvocation *context);
gboolean	 ods_session_change_current_folder_backward	(OdsSession *session,
															DBusGMethodInvocation *context);
gboolean	 ods_session_change_current_folder_to_root	(OdsSession *session,
															DBusGMethodInvocation *context);
gchar		*ods_session_get_current_path				(OdsSession *session);
gboolean	 ods_session_copy_remote_file				(OdsSession *session,
															const gchar *remote_filename,
															const gchar *local_path,
															DBusGMethodInvocation *context);
gboolean	 ods_session_copy_remote_file_by_type 		(OdsSession *session,
															const gchar *type,
															const gchar *local_path,
															DBusGMethodInvocation *context);
gboolean	 ods_session_create_folder					(OdsSession *session,
															const gchar *folder_name,
															DBusGMethodInvocation *context);
gboolean	 ods_session_retrieve_folder_listing		(OdsSession *session,
															DBusGMethodInvocation *context);
gboolean	 ods_session_get_capability					(OdsSession *session,
															DBusGMethodInvocation *context);
gboolean	 ods_session_get_imaging_capabilities		(OdsSession *session,
															DBusGMethodInvocation *context);
gboolean	 ods_session_send_file_ext					(OdsSession *session,
															const gchar *local_path,
															const gchar *remote_filename,
															const gchar *type,
															DBusGMethodInvocation *context);
gboolean	 ods_session_send_file						(OdsSession *session,
															const gchar *local_path,
															DBusGMethodInvocation *context);
gboolean	 ods_session_set_transfer_hints				(OdsSession *session,
															const gchar *fifo,
															const gchar *remote_filename,
															const gchar *type,
															guint64 size,
															gint64 mtime,
															gint64 ctime,
															DBusGMethodInvocation *context);
gboolean	 ods_session_delete_remote_file				(OdsSession *session,
															const gchar *remote_filename,
															DBusGMethodInvocation *context);
gboolean	 ods_session_remote_copy				(OdsSession *session,
															const gchar *remote_source,
															const gchar *remote_destination,
															DBusGMethodInvocation *context);
gboolean	 ods_session_remote_move				(OdsSession *session,
															const gchar *remote_source,
															const gchar *remote_destination,
															DBusGMethodInvocation *context);
gboolean	 ods_session_get_image_info					(OdsSession *session,
															const gchar *local_path,
															DBusGMethodInvocation *context);
gboolean	 ods_session_put_image						(OdsSession *session,
															const gchar *local_path,
															DBusGMethodInvocation *context);
gboolean	 ods_session_put_image_resized				(OdsSession *session,
															const gchar *local_path,
															guint16 width,
															guint16 height,
															const gchar *encoding,
															const gchar *transformation,
															DBusGMethodInvocation *context);
gboolean	 ods_session_put_linked_attachment			(OdsSession *session,
															const gchar *image_handle,
															const gchar *local_path,
															const gchar *content_type,
															const gchar *charset,
															DBusGMethodInvocation *context);
gboolean	 ods_session_remote_display_select_image	(OdsSession *session,
															const gchar *image_handle,
															DBusGMethodInvocation *context);
gboolean	 ods_session_remote_display_show_current_image (OdsSession *session,
															DBusGMethodInvocation *context);
gboolean	 ods_session_remote_display_show_next_image (OdsSession *session,
															DBusGMethodInvocation *context);
gboolean	 ods_session_remote_display_show_previous_image (OdsSession *session,
															DBusGMethodInvocation *context);
GHashTable	*ods_session_get_transfer_info				(OdsSession *session);
gboolean	 ods_session_is_busy						(OdsSession *session);
gboolean	 ods_session_cancel_internal				(OdsSession *session);
gboolean	 ods_session_cancel							(OdsSession *session,
															DBusGMethodInvocation *context);
void		 ods_session_set_protocol 						(OdsSession *session, 
															gint protocol);

G_END_DECLS

#endif /* __ODS_SESSION_H */


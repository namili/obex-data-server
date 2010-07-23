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

#ifndef __ODS_MANAGER_H
#define __ODS_MANAGER_H

#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "ods-common.h"

G_BEGIN_DECLS

#define	ODS_MANAGER_DBUS_PATH			"/org/openobex"
#define	ODS_MANAGER_DBUS_INTERFACE		"org.openobex.Manager"

#define ODS_MANAGER_OPP_STR		"opp"
#define ODS_MANAGER_FTP_STR		"ftp"
#define ODS_MANAGER_PBAP_STR	"pbap"
#define ODS_MANAGER_BIP_STR		"bip"

#define ODS_MANAGER_BIP_IMAGEPUSH_STR		"imagepush"
#define ODS_MANAGER_BIP_REMOTEDISPLAY_STR	"remotedisplay"

#define ODS_TYPE_MANAGER	 (ods_manager_get_type ())
#define ODS_MANAGER(o)		 (G_TYPE_CHECK_INSTANCE_CAST ((o), ODS_TYPE_MANAGER, OdsManager))
#define ODS_MANAGER_CLASS(k)	 (G_TYPE_CHECK_CLASS_CAST((k), ODS_TYPE_MANAGER, OdsManagerClass))
#define ODS_IS_MANAGER(o)	 (G_TYPE_CHECK_INSTANCE_TYPE ((o), ODS_TYPE_MANAGER))
#define ODS_IS_MANAGER_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), ODS_TYPE_MANAGER))
#define ODS_MANAGER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), ODS_TYPE_MANAGER, OdsManagerClass))

typedef struct OdsManagerPrivate OdsManagerPrivate;

typedef struct
{
	 GObject		 parent;
	 OdsManagerPrivate	*priv;
} OdsManager;

typedef struct
{
	GObjectClass	parent_class;
	void		(* session_connected)	(OdsManager	*manager,
							 			const gchar *session_object);
	void		(* session_closed)		(OdsManager	*manager,
							 			const gchar *session_object);
	void		(* session_connect_error)(OdsManager *manager,
											const gchar *session_object,
											const gchar *error_name,
											const gchar *error_message);
	void		(* disposed)			(OdsManager	*manager);
	DBusGConnection *connection;
} OdsManagerClass;


GType		 ods_manager_get_type		  	(void);
OdsManager	*ods_manager_new				(void);
gboolean	 ods_manager_is_initialized		(OdsManager *manager);

gboolean	 ods_manager_create_bluetooth_session (OdsManager *manager,
											const gchar *target_address,
											const gchar *source_address,
											const gchar *pattern,
											DBusGMethodInvocation *context);
gboolean	 ods_manager_create_bluetooth_imaging_session (OdsManager *manager,
											const gchar *target_address,
											const gchar *source_address,
											const gchar *bip_feature,
											DBusGMethodInvocation *context);
gboolean	 ods_manager_create_usb_session (OdsManager *manager,
											const gint interface_number,
											const gchar *pattern,
											DBusGMethodInvocation *context);
gboolean	 ods_manager_create_tty_session (OdsManager *manager,
											const gchar *tty_dev,
											const gchar *pattern,
											DBusGMethodInvocation *context);
guint		 ods_manager_get_usb_interfaces_num (OdsManager *manager);
GHashTable	*ods_manager_get_usb_interface_info (OdsManager *manager,
											const gint interface_number);
gboolean	 ods_manager_cancel_session_connect (OdsManager *manager,
											const gchar *session_object);
gboolean	 ods_manager_create_bluetooth_server (OdsManager *manager,
											const gchar *source_address,
											const gchar *pattern,
											gboolean require_pairing,
											DBusGMethodInvocation *context);
gboolean	 ods_manager_create_tty_server (OdsManager *manager,
											const gchar *tty_dev,
											const gchar *pattern,
											DBusGMethodInvocation *context);
void		 ods_manager_dispose			(OdsManager	*manager);
GHashTable	*ods_manager_get_session_info (OdsManager *manager, gchar *session_object);
GHashTable	*ods_manager_get_server_info (OdsManager *manager, gchar *server_object);
gchar		**ods_manager_get_session_list (OdsManager *manager);
gchar		**ods_manager_get_server_list (OdsManager *manager);
gchar		*ods_manager_get_version (OdsManager *manager);

G_END_DECLS

#endif /* __ODS_MANAGER_H */


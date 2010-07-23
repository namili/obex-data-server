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

#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib-bindings.h>

#include <bluetooth/bluetooth.h>

#include "../src/ods-marshal.h"

GMainLoop *loop;
gint total_bytes_global = -1;
const gchar* filename;
DBusGProxy *session_proxy;

static void
session_connected_cb (DBusGProxy *proxy, const gchar *session_object, gpointer user_data)
{
	gboolean	ret;
	GError		*error = NULL;
	//gchar		*listing;
	
	/* Let's see if this is for session that we created */
	if (strcmp (session_object, dbus_g_proxy_get_path (session_proxy)))
		return;
	g_message ("Session connected: %s", session_object);
	/*g_message ("RetrieveFolderListing ()");
	ret = dbus_g_proxy_call (session_proxy, "RetrieveFolderListing", &error, 
								G_TYPE_INVALID,
								G_TYPE_STRING, &listing,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	} else {
		g_message ("Here goes the listing:\n%s", listing);
		g_free (listing);
	}
	
	g_message ("GetCurrentPath ()");
	ret = dbus_g_proxy_call (session_proxy, "GetCurrentPath", &error,
								G_TYPE_INVALID,
								G_TYPE_STRING, &listing,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	} else {
		g_message ("Current path: %s", listing);
		g_free (listing);
	}*/
	
	/*g_message ("ChangeCurrentFolder (\"Data\")");
	ret = dbus_g_proxy_call (session_proxy, "ChangeCurrentFolder", &error,
								G_TYPE_STRING, "Data",
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}
	
	g_message ("GetCurrentPath ()");
	ret = dbus_g_proxy_call (session_proxy, "GetCurrentPath", &error,
								G_TYPE_INVALID,
								G_TYPE_STRING, &listing,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	} else {
		g_message ("Current path: %s", listing);
		g_free (listing);
	}
	
	g_message ("RetrieveFolderListing ()");
	ret = dbus_g_proxy_call (session_proxy, "RetrieveFolderListing", &error, 
								G_TYPE_INVALID,
								G_TYPE_STRING, &listing,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	} else {
		g_message ("Here goes the listing:\n%s", listing);
		g_free (listing);
	}
	
	
	
	
	
	g_message ("ChangeCurrentFolder (\"../Pictures\")");
	ret = dbus_g_proxy_call (session_proxy, "ChangeCurrentFolder", &error,
								G_TYPE_STRING, "../Pictures",
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error (%s): %s", dbus_g_error_get_name (error),
					error->message);
		g_clear_error (&error);
	}
	
	g_message ("GetCurrentPath ()");
	ret = dbus_g_proxy_call (session_proxy, "GetCurrentPath", &error,
								G_TYPE_INVALID,
								G_TYPE_STRING, &listing,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	} else {
		g_message ("Current path: %s", listing);
		g_free (listing);
	}
	
	g_message ("RetrieveFolderListing ()");
	ret = dbus_g_proxy_call (session_proxy, "RetrieveFolderListing", &error, 
								G_TYPE_INVALID,
								G_TYPE_STRING, &listing,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	} else {
		g_message ("Here goes the listing:\n%s", listing);
		g_free (listing);
	}*/
	
	/*g_message ("CopyRemoteFile (\"060820_143442.jpg\", \"/home/skirsdeda/Desktop/x.jpg\")");
	ret = dbus_g_proxy_call (session_proxy, "CopyRemoteFile", &error,
								G_TYPE_STRING, "060820_143442.jpg",
								G_TYPE_STRING, "/home/skirsdeda/Desktop/x.jpg",
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}*/
	
	/*gchar *capabilities;
	g_message ("GetImagingCapabilities ()");
	ret = dbus_g_proxy_call (session_proxy, "GetImagingCapabilities", &error,
								G_TYPE_INVALID,
								G_TYPE_STRING, &capabilities,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	} else {
		g_message ("Imaging capabilities:\n%s", capabilities);
		g_free (capabilities);
	}*/
	
	/*ret = dbus_g_proxy_call (session_proxy, "SetTransferHints", &error,
								G_TYPE_STRING, "blah",
								G_TYPE_STRING, "",
								G_TYPE_STRING, "",
								G_TYPE_UINT64, (guint64)0,
								G_TYPE_INT64, (gint64)-1,
								G_TYPE_INT64, (gint64)-1,
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}*/
	
	g_message ("SendFile (\"%s\")", filename);
	ret = dbus_g_proxy_call (session_proxy, "SendFile", &error,
								G_TYPE_STRING, filename,
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}
}

static void
session_connect_error_cb (DBusGProxy *proxy, const gchar *session_object,
							const char *error_name, const char *error_message,
							gpointer user_data)
{
	/* Let's see if this is for session that we created */
	if (strcmp (session_object, dbus_g_proxy_get_path (session_proxy)))
		return;
	g_message ("Session connect error: %s: %s", error_name, error_message);
}

static void
session_closed_cb (DBusGProxy *proxy, const char *session_object, gpointer user_data)
{
	g_message ("Session removed: %s", session_object);
	g_main_loop_quit (loop);
}

static void
transfer_started_cb (DBusGProxy *proxy, const char *filename,
						const char *local_path, guint64 total_bytes,
						gpointer user_data)
{
	g_message ("Transfer started: (%s, %s, %" G_GUINT64_FORMAT ")", filename, local_path,
				total_bytes);
	total_bytes_global = total_bytes;
}

static void
transfer_progress_cb (DBusGProxy *proxy, guint64 bytes_transferred,
						gpointer user_data)
{
	if (total_bytes_global != -1) {
		gdouble progress = (gdouble)bytes_transferred / total_bytes_global * 100;
		g_message ("Transfer progress: %.1f %%", progress);
	} else {
		g_message ("Transfer progress");
	}
}

static void
transfer_completed_cb (DBusGProxy *proxy, gpointer user_data)
{
	gboolean	ret;
	GError		*error = NULL;
	//gchar		*listing;
	
	g_message ("Transfer completed");
	
	/*g_message ("ChangeCurrentFolder (\"Pictures\")");
	ret = dbus_g_proxy_call (proxy, "ChangeCurrentFolder", &error,
								G_TYPE_STRING, "Pictures",
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}
	
	g_message ("GetCurrentPath ()");
	ret = dbus_g_proxy_call (proxy, "GetCurrentPath", &error,
								G_TYPE_INVALID,
								G_TYPE_STRING, &listing,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	} else {
		g_message ("Current path: %s", listing);
		g_free (listing);
	}
	
	g_message ("CreateFolder (\"Nonsense\")");
	ret = dbus_g_proxy_call (proxy, "CreateFolder", &error,
								G_TYPE_STRING, "Nonsense", 
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}
	
	g_message ("RetrieveFolderListing ()");
	ret = dbus_g_proxy_call (proxy, "RetrieveFolderListing", &error, 
								G_TYPE_INVALID,
								G_TYPE_STRING, &listing,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	} else {
		g_message ("Here goes the listing:\n%s", listing);
		g_free (listing);
	}
	
	g_message ("DeleteRemoteFile (\"x.jpg\")");
	ret = dbus_g_proxy_call (proxy, "DeleteRemoteFile", &error,
								G_TYPE_STRING, "x.jpg",
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}*/
	/*g_message ("DeleteRemoteFile (\"x (1).jpg\")");
	ret = dbus_g_proxy_call (proxy, "DeleteRemoteFile", &error,
								G_TYPE_STRING, "x (1).jpg",
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}
	g_message ("DeleteRemoteFile (\"x (2).jpg\")");
	ret = dbus_g_proxy_call (proxy, "DeleteRemoteFile", &error,
								G_TYPE_STRING, "x (2).jpg",
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}*/
	
	/*g_message ("ChangeCurrentFolderBackward ()");
	ret = dbus_g_proxy_call (proxy, "ChangeCurrentFolderBackward", &error,
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}
	
	g_message ("RetrieveFolderListing ()");
	ret = dbus_g_proxy_call (proxy, "RetrieveFolderListing", &error, 
								G_TYPE_INVALID,
								G_TYPE_STRING, &listing,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	} else {
		g_message ("Here goes the listing:\n%s", listing);
		g_free (listing);
	}*/
	
	/*g_message ("ChangeCurrentFolderToRoot ()");
	ret = dbus_g_proxy_call (proxy, "ChangeCurrentFolderToRoot", &error,
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}
	
	g_message ("RetrieveFolderListing ()");
	ret = dbus_g_proxy_call (proxy, "RetrieveFolderListing", &error, 
								G_TYPE_INVALID,
								G_TYPE_STRING, &listing,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	} else {
		g_message ("Here goes the listing:\n%s", listing);
		g_free (listing);
	}*/
	
	g_message ("Disconnect ()");
	ret = dbus_g_proxy_call (proxy, "Disconnect", &error,
								G_TYPE_INVALID, G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}
}

static void
error_occurred_cb (DBusGProxy *proxy,
					const gchar *error_name, const gchar *error_message,
					gpointer user_data)
{
	g_message ("Error occurred");
	g_warning ("%s: %s", error_name, error_message);
	g_main_loop_quit (loop);
} 

static void
session_disconnected_cb (DBusGProxy *proxy, gpointer user_data)
{
	gboolean	ret;
	GError		*error = NULL;
	
	g_message ("Session disconnected");
	ret = dbus_g_proxy_call (proxy, "Close", &error, G_TYPE_INVALID,
								G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
	}
}

static gboolean
create_bluetooth_session (DBusGConnection *dbus_connection,
								DBusGProxy *dbus_proxy,
								const gchar *address,
								const gchar *pattern)
{
	int ret;
	gchar *session_object_path = NULL;
	GError *error = NULL;

	g_message ("CreateBluetoothSession (\"%s\", \"00:00:00:00:00:00\", \"%s\")",
				address, pattern);	
	ret = dbus_g_proxy_call (dbus_proxy, "CreateBluetoothSession", &error, 
							G_TYPE_STRING, address,
							G_TYPE_STRING, "00:00:00:00:00:00",
							G_TYPE_STRING, pattern,
							G_TYPE_INVALID,
							DBUS_TYPE_G_OBJECT_PATH, &session_object_path,
							G_TYPE_INVALID);
	if (!ret) {
		g_warning ("Error: %s", error->message);
		g_clear_error (&error);
		return FALSE;
	} else {
	
		g_message ("Object path: %s", session_object_path);
		session_proxy = dbus_g_proxy_new_for_name (dbus_connection, "org.openobex",
												 session_object_path, 
												 "org.openobex.Session");
		/* register marshallers so we can get TransferStarted and TransferProgress signals */
		dbus_g_object_register_marshaller (ods_marshal_VOID__STRING_STRING_UINT64,
											G_TYPE_NONE,
											G_TYPE_STRING,
											G_TYPE_STRING,
											G_TYPE_UINT64,
											G_TYPE_INVALID);
		dbus_g_object_register_marshaller (ods_marshal_VOID__UINT64,
													G_TYPE_NONE,
													G_TYPE_UINT64,
													G_TYPE_INVALID);
		dbus_g_object_register_marshaller (ods_marshal_VOID__STRING_STRING,
											G_TYPE_NONE,
											G_TYPE_STRING,
											G_TYPE_STRING,
											G_TYPE_INVALID);
		
		dbus_g_proxy_add_signal (session_proxy, "Disconnected", G_TYPE_INVALID);
		dbus_g_proxy_connect_signal (session_proxy, "Disconnected", G_CALLBACK (session_disconnected_cb),
				       NULL, NULL);
		dbus_g_proxy_add_signal (session_proxy, "TransferStarted", G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT64, G_TYPE_INVALID);
		dbus_g_proxy_connect_signal (session_proxy, "TransferStarted", G_CALLBACK (transfer_started_cb),
				       NULL, NULL);
		dbus_g_proxy_add_signal (session_proxy, "TransferProgress", G_TYPE_UINT64, G_TYPE_INVALID);
		dbus_g_proxy_connect_signal (session_proxy, "TransferProgress", G_CALLBACK (transfer_progress_cb),
				       NULL, NULL);
		dbus_g_proxy_add_signal (session_proxy, "TransferCompleted", G_TYPE_INVALID);
		dbus_g_proxy_connect_signal (session_proxy, "TransferCompleted", G_CALLBACK (transfer_completed_cb),
				       NULL, NULL);
		dbus_g_proxy_add_signal (session_proxy, "ErrorOccurred", G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INVALID);
		dbus_g_proxy_connect_signal (session_proxy, "ErrorOccurred", G_CALLBACK (error_occurred_cb),
						NULL, NULL);
		/*dbus_g_proxy_call (dbus_proxy, "CancelSessionConnect", &error,
									G_TYPE_STRING, session_object_path,
									G_TYPE_INVALID, G_TYPE_INVALID);*/
		if (session_object_path != NULL)
			g_free (session_object_path);
		return TRUE;
	}
}

/**
 * main:
 **/
int
main (int argc, char *argv[])
{

	if (argc != 4) {
		g_critical ( "Usage: %s AA:BB:CC:DD:EE:FF profile file.txt", argv[0]);
		return -1;
	}

	filename = argv[3];


	DBusGConnection *dbus_connection;
	DBusGProxy *dbus_proxy;
	GError *error = NULL;
	

	g_type_init ();

	dbus_connection = dbus_g_bus_get (DBUS_BUS_SESSION, &error);
	if (error) {
		g_warning ("%s", error->message);
		g_clear_error (&error);
	}
	
	dbus_proxy = dbus_g_proxy_new_for_name (dbus_connection, "org.openobex",
											 "/org/openobex", 
											 "org.openobex.Manager");
	dbus_g_object_register_marshaller (ods_marshal_VOID__STRING_STRING_STRING,
												G_TYPE_NONE,
												DBUS_TYPE_G_OBJECT_PATH,
												G_TYPE_STRING,
												G_TYPE_STRING,
												G_TYPE_INVALID);
	dbus_g_proxy_add_signal (dbus_proxy, "SessionConnected",
					DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (dbus_proxy, "SessionConnected",
					G_CALLBACK (session_connected_cb), NULL, NULL);
	dbus_g_proxy_add_signal (dbus_proxy, "SessionConnectError",
					DBUS_TYPE_G_OBJECT_PATH, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (dbus_proxy, "SessionConnectError",
					G_CALLBACK (session_connect_error_cb), NULL, NULL);
	dbus_g_proxy_add_signal (dbus_proxy, "SessionClosed", 
					DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (dbus_proxy, "SessionClosed",
					G_CALLBACK (session_closed_cb), NULL, NULL);
	
	if (!create_bluetooth_session (dbus_connection, dbus_proxy, argv[1], argv[2]))
	    return 1;

	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);


	return 0;
}

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

#include <errno.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib-bindings.h>

#include "ods-common.h"
#include "ods-manager.h"
#include "ods-logging.h"

static GMainLoop *main_loop;
static OdsManager *manager = NULL;

static void
manager_disposed_cb (OdsManager *manager, gpointer data)
{
	g_message ("quitting main loop");
	g_main_loop_quit (main_loop);
}

static void
sig_term (int sig)
{
	g_message ("me was killed");
	g_signal_connect (manager, "disposed", G_CALLBACK (manager_disposed_cb), NULL);
	ods_manager_dispose (manager);
}

static gboolean
ods_service_register (DBusGConnection *connection)
{
	DBusGProxy *bus_proxy = NULL;
	GError *error = NULL;
	guint request_name_result;

	bus_proxy = dbus_g_proxy_new_for_name (connection,
	                                       DBUS_SERVICE_DBUS,
	                                       DBUS_PATH_DBUS,
	                                       DBUS_INTERFACE_DBUS);

	if (!org_freedesktop_DBus_request_name (bus_proxy,
	                                        ODS_DBUS_SERVICE,
	                                        0, &request_name_result,
	                                        &error)) {
		g_critical ("Unable to register service: %s", error->message);
		g_clear_error (&error);
		g_object_unref (bus_proxy);
		return FALSE;
	}

	/* free the bus_proxy */
	g_object_unref (bus_proxy);

	/* already running */
	if (request_name_result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		g_critical ("Already running in this session");
		return FALSE;
	}

	return TRUE;
}

/**
 * main:
 **/
int
main (int argc, char *argv[])
{
	DBusGConnection *system_connection;
	DBusGConnection *session_connection;
	GError *error = NULL;
	GOptionContext *context;
	struct sigaction sa;

	gboolean no_daemon = FALSE;
	gboolean system_bus = FALSE;
	gboolean show_version = FALSE;
	gboolean log = FALSE;
	gboolean debug = FALSE;

	const GOptionEntry options[] = {
		{ "no-daemon", 'n', 0, G_OPTION_ARG_NONE, &no_daemon,
			"Do not daemonize", NULL },
		{ "system-bus", 's', 0, G_OPTION_ARG_NONE, &system_bus,
		  "Use system bus instead of the default session bus", NULL},
		{ "log", 'l', 0, G_OPTION_ARG_NONE, &log,
		  "Log all messages to syslog", NULL},
		{ "debug", 'd', 0, G_OPTION_ARG_NONE, &debug,
		  "Enable debugging messages", NULL},
		{ "version", 'v', 0, G_OPTION_ARG_NONE, &show_version,
		  "Show version of obex-data-server and exit immediately", NULL},
		{ NULL}
	};

	setlocale (LC_CTYPE, "");

#if defined(USE_IMAGEMAGICK) || defined (USE_GDKPIXBUF)
	/* threading is only used for BIP stuff */
	g_thread_init (NULL);
#endif

	context = g_option_context_new ("");
	g_option_context_add_main_entries (context, options, NULL);
	if (!g_option_context_parse (context, &argc, &argv, &error)) {
		g_warning ("%s", error->message);
		g_clear_error (&error);
	}
	g_option_context_free (context);

	g_type_init ();

	if (show_version) {
		printf (PACKAGE_STRING "\n");
		return 0;
	}

	if (!no_daemon && daemon (0, 0)) {
		g_critical ("Could not daemonize: %s", g_strerror (errno));
	}
	
	/* init logging stuff */
	ods_log_init (PACKAGE_NAME, log, debug);

	/* check dbus connections, exit if not valid */
	system_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &error);
	if (error) {
		g_critical ("%s", error->message);
		g_clear_error (&error);
		return -1;
	}

	if (!system_bus) {
		ODS_DBUS_BUS = DBUS_BUS_SESSION;
		g_message ("Using Session bus");
	} else {
		ODS_DBUS_BUS = DBUS_BUS_SYSTEM;
		g_message ("Using System bus");
	}

	session_connection = dbus_g_bus_get (ODS_DBUS_BUS, &error);

	if (error) {
		g_critical ("%s", error->message);
		g_clear_error (&error);
		return -1;
	}

	if (!ods_service_register (session_connection)) {
		return -1;
	}

	/* create a new manager object */
	manager = ods_manager_new ();
	if (!ods_manager_is_initialized (manager)) {
		g_critical ("Failed to initialize OdsManager object");
		g_object_unref (manager);
		return -1;
	}

	main_loop = g_main_loop_new (NULL, FALSE);

	memset (&sa, 0, sizeof (sa));
	sa.sa_handler = sig_term;
	sigaction (SIGTERM, &sa, NULL);
	sigaction (SIGINT,  &sa, NULL);

	g_main_loop_run (main_loop);

	g_object_unref (manager);
	ods_log_finalize ();

	return 0;
}

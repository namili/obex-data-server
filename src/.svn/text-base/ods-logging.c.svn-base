/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*-
 *
 * Copyright (C) 2009 Tadas Dailyda <tadas@dailyda.com>
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

#include <glib.h>
#include <stdio.h>
#include <syslog.h>

#include <openobex/obex.h>

static gboolean syslog_enabled = FALSE;
static gboolean debug_enabled = FALSE;

static struct {
	int			g_log_level;
	int			syslog_prio;
	const char	*prefix;
} log_levels[] = {
	{ G_LOG_LEVEL_MESSAGE,	LOG_INFO,		""			},
	{ G_LOG_LEVEL_WARNING,	LOG_WARNING,	"**Warning"	},
	{ G_LOG_LEVEL_ERROR,	LOG_ERR,		"**Error"	},
	{ G_LOG_LEVEL_DEBUG,	LOG_DEBUG,		"##DEBUG"	},
	{ G_LOG_LEVEL_CRITICAL,	LOG_CRIT,		"**Critical"},
	{ G_LOG_LEVEL_INFO,		LOG_INFO,		""			},
	{ 0xFF,					0xFF,			""			},
};

static void
log_handler (const gchar *log_domain, GLogLevelFlags log_level,
             const gchar *message, gpointer user_data)
{
	const char *prefix = "";
	int syslog_prio = LOG_INFO;
	int i;
	char *out = NULL;

	/* suppress debug messages if debugging is disabled */
	if (!debug_enabled && log_level == G_LOG_LEVEL_DEBUG)
		return;

	for (i = 0; log_levels[i].g_log_level != 0xFF; i++) {
		if (log_levels[i].g_log_level != log_level)
			continue;
		syslog_prio = log_levels[i].syslog_prio;
		prefix = log_levels[i].prefix;
	}

	if (*prefix != '\0') {
		out = g_strdup_printf ("%s: %s", prefix, message);
	}

	if (syslog_enabled)
		syslog (syslog_prio, "%s", out ? out : message);
	else
		printf ("%s\n", out ? out : message);

	g_free (out);
}

void
ods_log_init (const char *ident, gboolean enable_syslog, gboolean enable_debug)
{
	g_log_set_handler (NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL
	                   | G_LOG_FLAG_RECURSION, log_handler, NULL);
	if (enable_syslog)
		openlog (ident, LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
	else
		printf ("%s\n", PACKAGE_STRING);

	syslog_enabled = enable_syslog;
	debug_enabled = enable_debug;
}

void
ods_log_finalize ()
{
	if (syslog_enabled)
		closelog ();
}

static struct {
	int			evt;
	const char	*name;
} obex_event[] = {
	{ OBEX_EV_PROGRESS,		"PROGRESS"		},	/* Progress has been made */
	{ OBEX_EV_REQHINT,		"REQHINT"		},	/* An incoming request is about to come */
	{ OBEX_EV_REQ,			"REQ"			},	/* An incoming request has arrived */
	{ OBEX_EV_REQDONE,		"REQDONE"		},	/* Request has finished */
	{ OBEX_EV_LINKERR,		"LINKERR"		},	/* Link has been disconnected */
	{ OBEX_EV_PARSEERR,		"PARSEERR"		},	/* Malformed data encountered */
	{ OBEX_EV_ACCEPTHINT, 	"ACCEPTHINT"	},	/* Connection accepted */
	{ OBEX_EV_ABORT, 		"ABORT"			},	/* Request was aborted */
	{ OBEX_EV_STREAMEMPTY, 	"STREAMEMPTY"	},	/* Need to feed more data when sending a stream */
	{ OBEX_EV_STREAMAVAIL,	"STREAMAVAIL"	},	/* Time to pick up data when receiving a stream */
	{ OBEX_EV_UNEXPECTED,	"UNEXPECTED"	},	/* Unexpected data, not fatal */
	{ OBEX_EV_REQCHECK,		"REQCHECK"		},	/* First packet of an incoming request has been parsed */
	{ 0xFF,					""				},
};

/* Possible OBEX commands */
static struct {
	int			cmd;
	const char	*name;
} obex_command[] = {
	{ OBEX_CMD_CONNECT,		"CONNECT"	},
	{ OBEX_CMD_DISCONNECT,	"DISCONNECT"},
	{ OBEX_CMD_PUT,			"PUT"		},
	{ OBEX_CMD_GET,			"GET"		},
	{ OBEX_CMD_SETPATH,		"SETPATH"	},
	{ OBEX_CMD_SESSION,		"SESSION"	},
	{ OBEX_CMD_ABORT,		"ABORT"		},
	{ OBEX_FINAL,			"FINAL"		},
	{ 0xFF,					""			},
};

/* Possible OBEX responses */
static struct {
	int			rsp;
	const char	*name;
} obex_response[] = {
	{ OBEX_RSP_CONTINUE,				"CONTINUE"				},
	{ OBEX_RSP_SWITCH_PRO,				"SWITCH_PRO"			},
	{ OBEX_RSP_SUCCESS,					"SUCCESS"				},
	{ OBEX_RSP_CREATED, 				"CREATED"				},
	{ OBEX_RSP_ACCEPTED,				"ACCEPTED"				},
	{ OBEX_RSP_NON_AUTHORITATIVE,		"NON_AUTHORITATIVE"		},
	{ OBEX_RSP_NO_CONTENT,				"NO_CONTENT"			},
	{ OBEX_RSP_RESET_CONTENT,			"RESET_CONTENT"			},
	{ OBEX_RSP_PARTIAL_CONTENT,			"PARTIAL_CONTENT"		},
	{ OBEX_RSP_MULTIPLE_CHOICES,		"MULTIPLE_CHOICES"		},
	{ OBEX_RSP_MOVED_PERMANENTLY,		"MOVED_PERMANENTLY"		},
	{ OBEX_RSP_MOVED_TEMPORARILY,		"MOVED_TEMPORARILY"		},
	{ OBEX_RSP_SEE_OTHER,				"SEE_OTHER"				},
	{ OBEX_RSP_NOT_MODIFIED,			"NOT_MODIFIED"			},
	{ OBEX_RSP_USE_PROXY,				"USE_PROXY"				},
	{ OBEX_RSP_BAD_REQUEST,				"BAD_REQUEST"			},
	{ OBEX_RSP_UNAUTHORIZED,			"UNAUTHORIZED"			},
	{ OBEX_RSP_PAYMENT_REQUIRED,		"PAYMENT_REQUIRED"		},
	{ OBEX_RSP_FORBIDDEN,				"FORBIDDEN"				},
	{ OBEX_RSP_NOT_FOUND,				"NOT_FOUND"				},
	{ OBEX_RSP_METHOD_NOT_ALLOWED,		"METHOD_NOT_ALLOWED"	},
	{ OBEX_RSP_NOT_ACCEPTABLE,			"NOT_ACCEPTABLE"		},
	{ OBEX_RSP_PROXY_AUTH_REQUIRED,		"PROXY_AUTH_REQUIRED"	},
	{ OBEX_RSP_REQUEST_TIME_OUT,		"REQUEST_TIME_OUT"		},
	{ OBEX_RSP_CONFLICT,				"CONFLICT"				},
	{ OBEX_RSP_GONE,					"GONE"					},
	{ OBEX_RSP_LENGTH_REQUIRED,			"LENGTH_REQUIRED"		},
	{ OBEX_RSP_PRECONDITION_FAILED,		"PRECONDITION_FAILED"	},
	{ OBEX_RSP_REQ_ENTITY_TOO_LARGE,	"REQ_ENTITY_TOO_LARGE"	},
	{ OBEX_RSP_REQ_URL_TOO_LARGE,		"REQ_URL_TOO_LARGE"		},
	{ OBEX_RSP_UNSUPPORTED_MEDIA_TYPE,	"UNSUPPORTED_MEDIA_TYPE"},
	{ OBEX_RSP_INTERNAL_SERVER_ERROR,	"INTERNAL_SERVER_ERROR"	},
	{ OBEX_RSP_NOT_IMPLEMENTED,			"NOT_IMPLEMENTED"		},
	{ OBEX_RSP_BAD_GATEWAY,				"BAD_GATEWAY"			},
	{ OBEX_RSP_SERVICE_UNAVAILABLE,		"SERVICE_UNAVAILABLE"	},
	{ OBEX_RSP_GATEWAY_TIMEOUT,			"GATEWAY_TIMEOUT"		},
	{ OBEX_RSP_VERSION_NOT_SUPPORTED,	"VERSION_NOT_SUPPORTED"	},
	{ OBEX_RSP_DATABASE_FULL,			"DATABASE_FULL"			},
	{ OBEX_RSP_DATABASE_LOCKED,			"DATABASE_LOCKED"		},
	{ 0xFF,								""						},
};

void
ods_log_obex (const char *prefix, int evt, int cmd, int rsp)
{
	const char *evtstr = NULL, *cmdstr = NULL, *rspstr = NULL;
	int i;

	if (!debug_enabled)
		return;

	for (i = 0; obex_event[i].evt != 0xFF; i++) {
		if (obex_event[i].evt != evt)
			continue;
		evtstr = obex_event[i].name;
	}

	for (i = 0; obex_command[i].cmd != 0xFF; i++) {
		if (obex_command[i].cmd != cmd)
			continue;
		cmdstr = obex_command[i].name;
	}

	for (i = 0; obex_response[i].rsp != 0xFF; i++) {
		if (obex_response[i].rsp != rsp)
			continue;
		rspstr = obex_response[i].name;
	}

	if (prefix) {
		g_debug ("%s OBEX event: %s(0x%x), %s(0x%x), %s(0x%x)",
				 prefix, evtstr, evt, cmdstr, cmd, rspstr, rsp);
	}
	else {
		g_debug ("OBEX event: %s(0x%x), %s(0x%x), %s(0x%x)",
				 evtstr, evt, cmdstr, cmd, rspstr, rsp);
	}
}

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

#ifndef __ODS_OBEX_H
#define __ODS_OBEX_H

#include <glib.h>
#include <openobex/obex.h>
#include <stdint.h>

/* FTP CMD_ACTION */
#ifndef OBEX_CMD_ACTION
#define OBEX_CMD_ACTION      0x06

#define OBEX_HDR_ACTION_ID   0x94
#define OBEX_HDR_DESTNAME    0x15
#define OBEX_HDR_PERMISSIONS 0xD6

#define OBEX_ACTION_COPY     0x00
#define OBEX_ACTION_MOVE     0x01
#define OBEX_ACTION_SETPERM  0x02

#endif /* OBEX_CMD_ACTION */

/* CMD_ACTION permissions */
#define OBEX_PERM_READ		1
#define OBEX_PERM_WRITE		1 << 1
#define OBEX_PERM_DEL		1 << 2
#define OBEX_PERM_MODIFY	1 << 7

/* Transfer suspend results */
#define OBEX_SUSP_REJECTED	-1
#define OBEX_SUSP_ACCEPTED	1
#define OBEX_SUSP_FIFO_ERR	-2
#define OBEX_SUSP_FIFO_ACT	2

/* BIP-specific headers */
#define OBEX_HDR_IMG_DESCRIPTOR		0x71
#define OBEX_HDR_IMG_HANDLE			0x30

/* BIP app-parameters header for RemoteDisplay */
#define BIP_REMOTEDISPLAY_NEXTIMAGE		0x01
#define BIP_REMOTEDISPLAY_PREVIOUSIMAGE	0x02
#define BIP_REMOTEDISPLAY_SELECTIMAGE	0x03
#define BIP_REMOTEDISPLAY_CURRENTIMAGE	0x04
#define BIP_APPARAM_REMOTEDISPLAY_TAGID	0x08
typedef struct bip_apparam_remote_display {
	uint8_t	tag_id;
	uint8_t	length;
	uint8_t	value;
} __attribute__ ((packed)) bip_apparam_remote_display_t;

#define CONID_INVALID 0xFFFFFFFF

#define ODS_DEFAULT_RX_MTU 32767
#define ODS_DEFAULT_TX_MTU 32767
#define ODS_TTY_RX_MTU 65535
#define ODS_TTY_TX_MTU 65535

/* Request timeout (when ods considers request as timed out and kills connection) */
/* in seconds */
#define ODS_OBEX_TIMEOUT 15

#define CAP_TYPE "x-obex/capability"
#define OBP_TYPE "x-obex/object-profile"
#define LST_TYPE "x-obex/folder-listing"
/* BIP-specific object types */
#define BIP_IMG_TYPE			"x-bt/img-img"
#define BIP_THM_TYPE			"x-bt/img-thm"
#define BIP_ATTACHMENT_TYPE		"x-bt/img-attachment"
#define BIP_LISTING_TYPE		"x-bt/img-listing"
#define BIP_PROPERTIES_TYPE		"x-bt/img-properties"
#define BIP_CAPABILITIES_TYPE	"x-bt/img-capabilities"
#define BIP_MONITORING_TYPE		"x-bt/img-monitoring"
#define BIP_DISPLAY_TYPE		"x-bt/img-display"
#define BIP_PRINT_TYPE			"x-bt/img-print"
#define BIP_PARTIAL_TYPE		"x-bt/img-partial"
#define BIP_ARCHIVE_TYPE		"x-bt/img-archive"
#define BIP_STATUS_TYPE			"x-bt/img-status"


typedef struct
{
	obex_t			*obex_handle;
	guint16			tx_max;
	guint16			rx_max;
	guint32			connection_id;
	obex_event_t	obex_event;
	GIOFunc			io_callback;
	guint			io_watch;
	gboolean		usb_read_more; /* USB trasport specific (set in session->obex_usbevent) */

	/* transfer basic info */
	guint8			obex_cmd; /* obex command */
	guint			timeout_id; /* source id for timeout function (>0 if set) (used for client requests) */
	gchar			*local;
	gchar			*remote;
	gchar			*type;
	guint64			target_size;
	time_t			modtime;
	gboolean		report_progress;
	gboolean		transfer_started_signal_emitted;
	guint			suspend_timeout_id;
	gint			suspend_result; /* transfers can be suspended for serversession accept/reject or when FIFO pipes are used in sessions */
	/* extended info */
	gchar			*img_handle;/* BIP-specific image handle */
	GHashTable		*ext_info;/* Any extended info which is not used internally */
	/* transfer data */
	guchar			*buf;	/* Data buffer for put and get requests */
	guint64			buf_size;
	gint			stream_fd;
	guint			fifo_watch;/* used to watch for fifo events */
	/* transfer status */
	guint64			counter;
	gboolean		cancelled;

} OdsObexContext;

typedef struct obex_connect_hdr {
    uint8_t  version;
    uint8_t  flags;
    uint16_t mtu;
} __attribute__ ((packed)) obex_connect_hdr_t;

typedef struct obex_setpath_hdr {
    uint8_t  flags;
    uint8_t constants;
} __attribute__ ((packed)) obex_setpath_hdr_t;


void		ods_obex_transfer_new (OdsObexContext *obex_context,
											const gchar *local,
											const gchar *remote,
											const gchar *type);
void		ods_obex_transfer_suspend (OdsObexContext *obex_context);
void		ods_obex_transfer_close	(OdsObexContext *obex_context);
void		ods_obex_transfer_add_info (OdsObexContext *obex_context,
											gchar *key,
											gchar *value);
GHashTable*	ods_obex_transfer_get_info (OdsObexContext *obex_context);
OdsObexContext *ods_obex_context_new (void);
gboolean	ods_obex_setup_fdtransport (OdsObexContext *obex_context,
											gint fd,
											guint16 rx_mtu,
											guint16 tx_mtu,
											obex_event_t eventcb,
											GIOFunc io_cb,
											gpointer user_data,
											GError **error);
gboolean	ods_obex_setup_usbtransport (OdsObexContext *obex_context,
											gint intf_num,
											obex_event_t eventcb,
											GIOFunc io_cb,
											gpointer user_data,
											GError **error);
void		ods_obex_close_transport (OdsObexContext *ctxt);
gchar		*ods_obex_get_buffer_as_string (OdsObexContext *obex_context);
gboolean	ods_obex_srv_new_file (OdsObexContext *obex_context,
											const gchar *path);
gint		ods_obex_connect_done (OdsObexContext *obex_context,
											obex_object_t *object);
gint		ods_obex_connect	(OdsObexContext *obex_context,
											const guchar *uuid,
											guint uuid_length);
gint		ods_obex_srv_connect (OdsObexContext *obex_context,
											obex_object_t *object,
											guint service);
gint		ods_obex_disconnect	(OdsObexContext *obex_context);
gint		ods_obex_readstream	(OdsObexContext *obex_context,
											obex_object_t *object);
gint		ods_obex_writestream(OdsObexContext *obex_context,
											obex_object_t *object);
gint		ods_obex_get		(OdsObexContext *obex_context,
											const gchar *local,
											const gchar *remote,
											const gchar *type,
											gboolean is_fifo);
gint		ods_obex_srv_get	(OdsObexContext *obex_context,
											obex_object_t *object,
											const gchar *current_path,
											const gchar *root_path,
											gboolean allow_write);
gint		ods_obex_put		(OdsObexContext *obex_context,
											const gchar *local,
											const gchar *remote,
											const gchar *type,
											guint64 size,
											time_t mtime,
											gboolean is_fifo,
											gint fifo_fd);
gint		ods_obex_srv_put	(OdsObexContext *obex_context,
											obex_object_t *object,
											const gchar *path,
											guint8 *action,
											gboolean no_response_on_success);
gint		ods_obex_setpath	(OdsObexContext *obex_context,
											const gchar *path,
											gboolean create);
gboolean	ods_obex_srv_setpath (OdsObexContext *obex_context,
											obex_object_t *object,
											const gchar *root_path,
											const gchar *current_path,
											gchar **new_path);
gint		ods_obex_put_image (OdsObexContext *obex_context,
											const gchar *local,
											const gchar *remote,
											const gchar *encoding,
											const gchar *pixel,
											guint64 size,
											const gchar *transformation);
gint		ods_obex_put_linked_thumbnail (OdsObexContext *obex_context,
											const gchar *local,
											const gchar *img_handle,
											guint64 size);
gint		ods_obex_put_linked_attachment (OdsObexContext *obex_context,
											const gchar *local,
											const gchar *img_handle,
											const gchar *name,
											const gchar *content_type,
											const gchar *charset,
											guint64 size,
											time_t ctime);
gint		ods_obex_remote_display (OdsObexContext *obex_context,
											const gchar *img_handle,
											guint8 action);
gint		ods_obex_action (OdsObexContext *obex_context,
											const gchar *src,
											const gchar *dst,
											guint8 action,
											guint32 perms);

#endif /* __ODS_OBEX_H */

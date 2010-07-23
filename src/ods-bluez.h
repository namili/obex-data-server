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

#ifndef __ODS_BLUEZ_H
#define __ODS_BLUEZ_H

#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

/* BIP SDP record bits */
#define BIP_SUPP_CAP_GENERIC_IMAGING	(1)
#define BIP_SUPP_CAP_CAPTURING			(1 << 1)
#define BIP_SUPP_CAP_PRINTING			(1 << 2)
#define BIP_SUPP_CAP_DISPLAYING			(1 << 3)

#define BIP_SUPP_FEAT_IMAGE_PUSH				(1)
#define BIP_SUPP_FEAT_IMAGE_PUSH_STORE			(1 << 1)
#define BIP_SUPP_FEAT_IMAGE_PUSH_PRINT			(1 << 2)
#define BIP_SUPP_FEAT_IMAGE_PUSH_DISPLAY		(1 << 3)
#define BIP_SUPP_FEAT_IMAGE_PULL				(1 << 4)
#define BIP_SUPP_FEAT_ADVANCED_IMAGE_PRINTING	(1 << 5)
#define BIP_SUPP_FEAT_AUTOMATIC_ARCHIVE			(1 << 6)
#define BIP_SUPP_FEAT_REMOTE_CAMERA				(1 << 7)
#define BIP_SUPP_FEAT_REMOTE_DISPLAY			(1 << 8)

#define BIP_SUPP_FUNC_GET_CAPABILITIES		(1)
#define BIP_SUPP_FUNC_PUT_IMAGE				(1 << 1)
#define BIP_SUPP_FUNC_PUT_LINKED_ATTACHMENT	(1 << 2)
#define BIP_SUPP_FUNC_PUT_LINKED_THUMBNAIL	(1 << 3)
#define BIP_SUPP_FUNC_REMOTE_DISPLAY		(1 << 4)
#define BIP_SUPP_FUNC_GET_IMAGES_LIST		(1 << 5)
#define BIP_SUPP_FUNC_GET_IMAGE_PROPERTIES	(1 << 6)
#define BIP_SUPP_FUNC_GET_IMAGE				(1 << 7)
#define BIP_SUPP_FUNC_GET_LINKED_THUMBNAIL	(1 << 8)
#define BIP_SUPP_FUNC_GET_LINKED_ATTACHMENT	(1 << 9)
#define BIP_SUPP_FUNC_DELETE_IMAGE			(1 << 10)
#define BIP_SUPP_FUNC_START_PRINT			(1 << 11)
#define BIP_SUPP_FUNC_START_ARCHIVE			(1 << 13)
#define BIP_SUPP_FUNC_GET_MONITORING_IMAGE	(1 << 14)
#define BIP_SUPP_FUNC_GET_STATUS			(1 << 16)

typedef struct ImagingSdpData_ {
	guint8	supp_capabilities;
	guint16	supp_features;
	guint32	supp_functions;
	guint64	data_capacity;
} ImagingSdpData;

typedef void (* OdsBluezFunc)	(gint, gint, const ImagingSdpData*, GError*, gpointer);

typedef struct OdsBluezCancellable_ {
	/* cancellable data */
	sdp_session_t	*session;
	GIOChannel		*io_channel;
	guint			io_watch;
	gint			fd;/* RFCOMM socket */
	/* other data */
	OdsBluezFunc	cb;
	gpointer		cb_data;
	bdaddr_t		target_address;
	bdaddr_t		source_address;
	uuid_t			uuid;
	guint			imaging_feature;
	ImagingSdpData	*imagingdata;
	gint			channel;
} OdsBluezCancellable;

OdsBluezCancellable* ods_bluez_get_client_socket	(const bdaddr_t *dst,
														const bdaddr_t *src,
														const uuid_t *uuid,
														guint imaging_feature,
														gint channel,
														OdsBluezFunc func,
														gpointer data);
void		 ods_bluez_cancel_get_client_socket		(OdsBluezCancellable *cancel);
gint		 ods_bluez_get_server_socket			(const gchar *address,
														guint8 channel);
guint32		 ods_bluez_add_service_record			(const gchar *device,
														gint service,
														ImagingSdpData *imagingdata);
void		 ods_bluez_remove_service_record		(const gchar *device,
														guint32 record_handle);
void		 ods_bluez_finalize ();

#endif /* __ODS_BLUEZ_H */

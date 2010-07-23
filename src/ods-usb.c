#include "config.h"

#ifdef USE_USB

#include <glib.h>
#include <stdio.h>		/* perror */
#include <errno.h>		/* errno and EADDRNOTAVAIL */
#include <string.h>
#include <usb.h>

#include "ods-usb.h"

struct ods_usb_intf_transport_t {
	struct ods_usb_intf_transport_t *prev, *next;	/* Next and previous interfaces in the list */
	struct usb_device *device;		/* USB device that has the interface */
	int configuration;			/* Device configuration */
	int configuration_description;		/* Configuration string descriptor number */
	int control_interface;			/* OBEX master interface */
	int control_setting;			/* OBEX master interface setting */
	int control_interface_description;	/* OBEX master interface string descriptor number
						 * If non-zero, use usb_get_string_simple() from
						 * libusb to retrieve human-readable description
						 */
	unsigned char *extra_descriptors;		/* Extra master interface descriptors */
	int extra_descriptors_len;		/* Length of extra descriptors */
	int data_interface;			/* OBEX data/slave interface */
	int data_idle_setting;			/* OBEX data/slave idle setting */
	int data_interface_idle_description;	/* OBEX data/slave interface string descriptor number
						 * in idle setting */
	int data_active_setting;		/* OBEX data/slave active setting */
	int data_interface_active_description;	/* OBEX data/slave interface string descriptor number
						 * in active setting */
	int data_endpoint_read;			/* OBEX data/slave interface read endpoint */
	int data_endpoint_write;		/* OBEX data/slave interface write endpoint */
	usb_dev_handle *dev_control;		/* libusb handler for control interace */
	usb_dev_handle *dev_data;		/* libusb handler for data interface */
	char *path;				/* Path, see path in obex_usb_intf_t */
};


/* "Union Functional Descriptor" from CDC spec 5.2.3.X
 * used to find data/slave OBEX interface */
#pragma pack(1)
struct cdc_union_desc {
	guint8      bLength;
	guint8      bDescriptorType;
	guint8      bDescriptorSubType;

	guint8      bMasterInterface0;
	guint8      bSlaveInterface0;
};
#pragma pack()

/* CDC class and subclass types */
#define USB_CDC_CLASS			0x02
#define USB_CDC_OBEX_SUBCLASS		0x0b

/* class and subclass specific descriptor types */
#define CDC_HEADER_TYPE			0x00
#define CDC_CALL_MANAGEMENT_TYPE	0x01
#define CDC_AC_MANAGEMENT_TYPE		0x02
#define CDC_UNION_TYPE			0x06
#define CDC_COUNTRY_TYPE		0x07
#define CDC_OBEX_TYPE			0x15
#define CDC_OBEX_SERVICE_ID_TYPE	0x19

/* Interface descriptor */
#define USB_DT_CS_INTERFACE		0x24
#define CDC_DATA_INTERFACE_TYPE		0x0a

#define WMC_DEFAULT_OBEX_SERVER_UUID \
{ 0x02, 0xae, 0xb3, 0x20, \
0xf6, 0x49, 0x11, 0xda, \
0x97, 0x4d, 0x08, 0x00, \
0x20, 0x0c, 0x9a, 0x66 }

#define USB_MAX_STRING_SIZE		256
#define USB_OBEX_TIMEOUT		10000 /* 10 seconds */

/*
 * Helper function to usbobex_find_interfaces
 */
static void find_eps(struct ods_usb_intf_transport_t *intf, struct usb_interface_descriptor data_intf, int *found_active, int *found_idle)
{
	struct usb_endpoint_descriptor *ep0, *ep1;

	if (data_intf.bNumEndpoints == 2) {
		ep0 = data_intf.endpoint;
		ep1 = data_intf.endpoint + 1;
		if ((ep0->bEndpointAddress & USB_ENDPOINT_IN) &&
		        ((ep0->bmAttributes & USB_ENDPOINT_TYPE_MASK) == USB_ENDPOINT_TYPE_BULK) &&
		        !(ep1->bEndpointAddress & USB_ENDPOINT_IN) &&
		        ((ep1->bmAttributes & USB_ENDPOINT_TYPE_MASK) == USB_ENDPOINT_TYPE_BULK)) {
			*found_active = 1;
			intf->data_active_setting = data_intf.bAlternateSetting;
			intf->data_interface_active_description = data_intf.iInterface;
			intf->data_endpoint_read = ep0->bEndpointAddress;
			intf->data_endpoint_write = ep1->bEndpointAddress;
		}
		if (!(ep0->bEndpointAddress & USB_ENDPOINT_IN) &&
		        ((ep0->bmAttributes & USB_ENDPOINT_TYPE_MASK) == USB_ENDPOINT_TYPE_BULK) &&
		        (ep1->bEndpointAddress & USB_ENDPOINT_IN) &&
		        ((ep1->bmAttributes & USB_ENDPOINT_TYPE_MASK) == USB_ENDPOINT_TYPE_BULK)) {
			*found_active = 1;
			intf->data_active_setting = data_intf.bAlternateSetting;
			intf->data_interface_active_description = data_intf.iInterface;
			intf->data_endpoint_read = ep1->bEndpointAddress;
			intf->data_endpoint_write = ep0->bEndpointAddress;
		}
	}
	if (data_intf.bNumEndpoints == 0) {
		*found_idle = 1;
		intf->data_idle_setting = data_intf.bAlternateSetting;
		intf->data_interface_idle_description = data_intf.iInterface;
	}
}

/*
 * Helper function to usbobex_find_interfaces
 */
static int find_obex_data_interface(unsigned char *buffer, int buflen, struct usb_config_descriptor config, struct ods_usb_intf_transport_t *intf)
{
	struct cdc_union_desc *union_header = NULL;
	int i, a;
	int found_active = 0;
	int found_idle = 0;

	if (!buffer) {
		g_debug("Weird descriptor references");
		return -EINVAL;
	}

	while (buflen > 0) {
		if (buffer [1] != USB_DT_CS_INTERFACE) {
			g_debug("skipping garbage");
			goto next_desc;
		}
		switch (buffer [2]) {
			case CDC_UNION_TYPE: /* we've found it */
				if (union_header) {
					g_debug("More than one union descriptor, skiping ...");
					goto next_desc;
				}
				union_header = (struct cdc_union_desc *)buffer;
				break;
			case CDC_OBEX_TYPE: /* maybe check version */
			case CDC_OBEX_SERVICE_ID_TYPE: /* This one is handled later */
			case CDC_HEADER_TYPE:
				break; /* for now we ignore it */
			default:
				g_debug("Ignoring extra header, type %d, length %d", buffer[2], buffer[0]);
				break;
		}
next_desc:
		buflen -= buffer[0];
		buffer += buffer[0];
	}

	if (!union_header) {
		g_debug("No union descriptor, giving up");
		return -ENODEV;
	}
	/* Found the slave interface, now find active/idle settings and endpoints */
	intf->data_interface = union_header->bSlaveInterface0;
	/* Loop through all of the interfaces */
	for (i = 0; i < config.bNumInterfaces; i++) {
		/* Loop through all of the alternate settings */
		for (a = 0; a < config.interface[i].num_altsetting; a++) {
			/* Check if this interface is OBEX data interface*/
			/* and find endpoints */
			if (config.interface[i].altsetting[a].bInterfaceNumber == intf->data_interface)
				find_eps(intf, config.interface[i].altsetting[a], &found_active, &found_idle);
		}
	}
	if (!found_idle) {
		g_debug("No idle setting");
		return -ENODEV;
	}
	if (!found_active) {
		g_debug("No active setting");
		return -ENODEV;
	}

	return 0;
}

/*
 * Helper function to usbobex_find_interfaces
 */
static int get_intf_string(struct usb_dev_handle *usb_handle, char **string, int id)
{
	if (id) {
		if ((*string = malloc(USB_MAX_STRING_SIZE)) == NULL)
			return -ENOMEM;
		*string[0] = '\0';
		return usb_get_string_simple(usb_handle, id, *string, USB_MAX_STRING_SIZE);
	}

	return 0;
}

/*
 * Helper function to usbobex_find_interfaces
 */
static struct ods_usb_intf_transport_t *check_intf(struct usb_device *dev,
			        int c, int i, int a,
			        char *bus, char *device,
			        struct ods_usb_intf_transport_t *current) {
	struct ods_usb_intf_transport_t *next = NULL;

	if ((dev->config[c].interface[i].altsetting[a].bInterfaceClass == USB_CDC_CLASS)
	        && (dev->config[c].interface[i].altsetting[a].bInterfaceSubClass == USB_CDC_OBEX_SUBCLASS)) {
		int err;
		unsigned char *buffer = dev->config[c].interface[i].altsetting[a].extra;
		int buflen = dev->config[c].interface[i].altsetting[a].extralen;

		next = malloc(sizeof(struct ods_usb_intf_transport_t));
		if (next == NULL)
			return current;
		next->device = dev;
		next->configuration = dev->config[c].bConfigurationValue;
		next->configuration_description = dev->config[c].iConfiguration;
		next->control_interface = dev->config[c].interface[i].altsetting[a].bInterfaceNumber;
		next->control_interface_description = dev->config[c].interface[i].altsetting[a].iInterface;
		next->control_setting = dev->config[c].interface[i].altsetting[a].bAlternateSetting;
		next->extra_descriptors = buffer;
		next->extra_descriptors_len = buflen;

		err = find_obex_data_interface(buffer, buflen, dev->config[c], next);
		if (err)
			free(next);
		else {
			char path[200], *s, *shortdev;

			/* On MacOS X we might get 002-04a9-3139-00-00 instead of 002 for the dev. */
			shortdev = strdup (device);
			s = strchr(shortdev, '-');
			if (s)
				*s='\0';

			/* Create the usb: path for the device */
			snprintf (path, sizeof(path), "usb:%s,%s,%d", bus, shortdev, dev->config[c].interface[i].altsetting[a].bInterfaceNumber);
			free (shortdev);
			next->path = strdup (path);

			if (current)
				current->next = next;
			next->prev = current;
			next->next = NULL;
			current = next;
		}
	}

	return current;
}

/*
 * Helper function to usbobex_find_interfaces
 */
static void find_obex_service_descriptor(unsigned char *buffer, int buflen, ods_usb_intf_service_t **service)
{
	if (!buffer) {
		g_debug("Weird descriptor references");
		return ;
	}
	while (buflen > 0) {
		if (buffer[1] != USB_DT_CS_INTERFACE) {
			g_debug("skipping garbage");
			goto next_desc;
		}
		switch (buffer[2]) {
			case CDC_OBEX_SERVICE_ID_TYPE: /* we've found it */
				if (buflen < 22) /* Check descriptor size */
					g_debug("Invalid service id descriptor");
				else if (*service == NULL) {
					*service = malloc(sizeof(ods_usb_intf_service_t));
					if (*service != NULL) {
						const guint8 default_uuid[16] = WMC_DEFAULT_OBEX_SERVER_UUID;
						(*service)->role = buffer[3];
						memcpy((*service)->uuid, buffer+4, 16);
						(*service)->version = (buffer[20]<<8)|(buffer[21]);
						if (memcmp((*service)->uuid, default_uuid, 16) == 0 )
							(*service)->is_default_uuid = 1;
						else
							(*service)->is_default_uuid = 0;
					}
				}
				break;
			case CDC_OBEX_TYPE: /* maybe check version */
			case CDC_UNION_TYPE:
			case CDC_HEADER_TYPE:
				break;
			default:
				g_debug("Ignoring extra header, type %d, length %d", buffer[2], buffer[0]);
				break;
		}
next_desc:
		buflen -= buffer[0];
		buffer += buffer[0];
	}
}


/*
 * Function usbobex_find_interfaces ()
 *
 *    Find available USBOBEX interfaces on the system
 */
GList *ods_usbobex_find_interfaces(void)
{
	struct usb_bus *busses;
	struct usb_bus *bus;
	struct usb_device *dev;
	int c, i, a;
	struct ods_usb_intf_transport_t *current = NULL;
	struct ods_usb_intf_transport_t *tmp = NULL;
	struct usb_dev_handle *usb_handle;
	GList *list = NULL;

	usb_init();
	usb_find_busses();
	usb_find_devices();

	busses = usb_get_busses();

	for (bus = busses; bus; bus = bus->next) {
		for (dev = bus->devices; dev; dev = dev->next) {
			/* Loop through all of the configurations */
			for (c = 0; c < dev->descriptor.bNumConfigurations; c++) {
				/* Loop through all of the interfaces */
				for (i = 0; i < dev->config[c].bNumInterfaces; i++) {
					/* Loop through all of the alternate settings */
					for (a = 0; a < dev->config[c].interface[i].num_altsetting; a++) {
						/* Check if this interface is OBEX */
						/* and find data interface */
						current = check_intf(dev, c, i, a, bus->dirname, dev->filename, current);
					}
				}
			}
		}
	}

	/* Rewind the double-linked list */
	while (current && current->prev)
		current = current->prev;

	while (current) {
		ods_usb_info *item;

		usb_handle = usb_open(current->device);

		item = g_new0 (ods_usb_info, 1);

		get_intf_string(usb_handle, &item->manufacturer,
		                current->device->descriptor.iManufacturer);
		get_intf_string(usb_handle, &item->product,
		                current->device->descriptor.iProduct);
		get_intf_string(usb_handle, &item->serial,
		                current->device->descriptor.iSerialNumber);
		get_intf_string(usb_handle, &item->configuration,
		                current->configuration_description);
		get_intf_string(usb_handle, &item->control_interface,
		                current->control_interface_description);
		get_intf_string(usb_handle, &item->data_interface_idle,
		                current->data_interface_idle_description);
		get_intf_string(usb_handle, &item->data_interface_active,
		                current->data_interface_active_description);
		item->path = current->path;
		find_obex_service_descriptor(current->extra_descriptors,
		                             current->extra_descriptors_len,
		                             &item->service);
		usb_close(usb_handle);
		current = current->next;
		list = g_list_prepend (list, item);
	}
	list = g_list_reverse (list);

	/* Rewind the double-linked list */
	while (current && current->prev)
		current = current->prev;
	while (current) {
		tmp = current->next;
		free(current);
		current = tmp;
	}

	return list;
}

/*
 * Function usbobex_free_interfaces ()
 *
 *    Free the list of discovered USBOBEX interfaces on the system
 */
static void ods_usbobex_free_interface(ods_usb_info *item)
{
	free(item->manufacturer);
	free(item->product);
	free(item->serial);
	free(item->configuration);
	free(item->control_interface);
	free(item->data_interface_idle);
	free(item->data_interface_active);
	free(item->service);
	free(item->path);
	free(item);
}

void ods_usbobex_free_interfaces(GList *list)
{
	if (list == NULL)
		return;

	g_list_foreach (list, (GFunc) ods_usbobex_free_interface, NULL);
	g_list_free (list);
}
#endif /* USE_USB */


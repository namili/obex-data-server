#include "config.h"

#ifdef USE_USB

#include <glib.h>
#include <usb.h>

/** USB-specific OBEX service information
 * provided by optional Service Identification Functional Descriptor
 * (CDC WMC specification section 6.5.2.5)
 */
typedef struct {
	/* Role bit mask: bit 0 is set if client, unset if server */
	guint8 role;
	/* Service UUID */
	guint8 uuid[16];
	/** Service version */
	guint16 version;
	/** Set if the service provides/expects
	*  an OBEX Default Server (spec section 6.5.2.5.2) */
	int is_default_uuid;
} ods_usb_intf_service_t;

struct ods_usb_info {
	char *manufacturer;
	char *product;
	char *serial;
	char *configuration;
	char *control_interface;
	char *data_interface_idle;
	char *data_interface_active;
	ods_usb_intf_service_t *service;
	char *path;
};

typedef struct ods_usb_info ods_usb_info;


void ods_usbobex_free_interfaces(GList *list);
GList *ods_usbobex_find_interfaces(void);
#endif /* USE_USB */

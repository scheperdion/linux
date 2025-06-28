/* --------  Realtek-style descriptors  -------- */
#define RTL_VID    0x0bda
#define RTL_PID    0xc811

static struct usb_device_descriptor dev_desc = {
        .bLength            = USB_DT_DEVICE_SIZE,
        .bDescriptorType    = USB_DT_DEVICE,
        .bcdUSB             = __constant_cpu_to_le16(0x0200),
        .bDeviceClass       = 0xff,
        .bDeviceSubClass    = 0xff,
        .bDeviceProtocol    = 0xff,
        .bMaxPacketSize0    = 64,
        .idVendor           = __constant_cpu_to_le16(        RTL_VID),
        .idProduct          = __constant_cpu_to_le16(RTL_PID),
        .bcdDevice          = __constant_cpu_to_le16(0x0200),
        .iManufacturer      = 1,
        .iProduct           = 2,
        .iSerialNumber      = 3,
        .bNumConfigurations = 1,
};

/* configuration + 3 interface descriptors + 3 endpoint descs */
struct __attribute__((packed)) {
        struct usb_config_descriptor  cfg;
        struct usb_interface_descriptor if0;
        struct usb_endpoint_descriptor  ep1_out;
        struct usb_endpoint_descriptor  ep2_in;
        struct usb_interface_descriptor if1;
        struct usb_endpoint_descriptor  ep3_int;
} cfg_desc = {
        .cfg = {
                .bLength             = USB_DT_CONFIG_SIZE,
                .bDescriptorType     = USB_DT_CONFIG,
                .wTotalLength        = 0,   /* fixed below */
                .bNumInterfaces      = 2,
                .bConfigurationValue = 1,
                .iConfiguration      = 4,
                .bmAttributes        = USB_CONFIG_ATT_ONE |
                                       USB_CONFIG_ATT_SELFPOWER,
                .bMaxPower           = 0xfa,
        },
        .if0 = {
                .bLength            = USB_DT_INTERFACE_SIZE,
                .bDescriptorType    = USB_DT_INTERFACE,
                .bInterfaceNumber   = 0,
                .bNumEndpoints      = 2,
                .bInterfaceClass    = 0xff,
                .bInterfaceSubClass = 0xff,
                .bInterfaceProtocol = 0xff,
                .iInterface         = 5,
        },
        .ep1_out = {
                .bLength          = USB_DT_ENDPOINT_SIZE,
                .bDescriptorType  = USB_DT_ENDPOINT,
                .bEndpointAddress = 1 | USB_DIR_OUT,
                .bmAttributes     = USB_ENDPOINT_XFER_BULK,
                .wMaxPacketSize   = __constant_cpu_to_le16(512),
        },
        .ep2_in = {
                .bLength          = USB_DT_ENDPOINT_SIZE,
                .bDescriptorType  = USB_DT_ENDPOINT,
                .bEndpointAddress = 2 | USB_DIR_IN,
                .bmAttributes     = USB_ENDPOINT_XFER_BULK,
                .wMaxPacketSize   = __constant_cpu_to_le16(512),
        },
        .if1 = {
                .bLength            = USB_DT_INTERFACE_SIZE,
                .bDescriptorType    = USB_DT_INTERFACE,
                .bInterfaceNumber   = 1,
                .bNumEndpoints      = 1,
                .bInterfaceClass    = 0xff,
                .bInterfaceSubClass = 0xff,
                .bInterfaceProtocol = 0xff,
                .iInterface         = 6,
        },
        .ep3_int = {
                .bLength          = USB_DT_ENDPOINT_SIZE,
                .bDescriptorType  = USB_DT_ENDPOINT,
                .bEndpointAddress = 3 | USB_DIR_IN,
                .bmAttributes     = USB_ENDPOINT_XFER_INT,
                .wMaxPacketSize   = __constant_cpu_to_le16(64),
                .bInterval        = 6,
        },
};

static const struct usb_string strings[] = {
        { 1, "Realtek" },
        { 2, "802.11ac WLAN Adapter" },
        { 3, "00E04C0001" },
        { 4, "Config 1" },
        { 5, "Data Interface" },
        { 6, "Status Interface" },
        { }
};
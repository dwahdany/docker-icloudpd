// A FIDO HID interface (what the computer sees as a security key) plus a CDC
// serial port (where the software authenticator on the other end listens).
#include <string.h>

#include "pico/unique_id.h"
#include "tusb.h"

static tusb_desc_device_t const desc_device = {
    .bLength = sizeof(tusb_desc_device_t),
    .bDescriptorType = TUSB_DESC_DEVICE,
    .bcdUSB = 0x0200,
    // Composite device with an interface association (needed for CDC)
    .bDeviceClass = TUSB_CLASS_MISC,
    .bDeviceSubClass = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0 = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor = 0x1209,   // pid.codes
    .idProduct = 0x0001,  // pid.codes test PID
    .bcdDevice = 0x0100,
    .iManufacturer = 1,
    .iProduct = 2,
    .iSerialNumber = 3,
    .bNumConfigurations = 1,
};

uint8_t const *tud_descriptor_device_cb(void) { return (uint8_t const *)&desc_device; }

static uint8_t const desc_hid_report[] = {TUD_HID_REPORT_DESC_FIDO_U2F(CFG_TUD_HID_EP_BUFSIZE)};

uint8_t const *tud_hid_descriptor_report_cb(uint8_t itf) {
  (void)itf;
  return desc_hid_report;
}

enum { ITF_HID, ITF_CDC, ITF_CDC_DATA, ITF_TOTAL };

#define EP_HID_OUT 0x01
#define EP_HID_IN 0x81
#define EP_CDC_NOTIF 0x82
#define EP_CDC_OUT 0x03
#define EP_CDC_IN 0x83
#define CONFIG_LEN (TUD_CONFIG_DESC_LEN + TUD_HID_INOUT_DESC_LEN + TUD_CDC_DESC_LEN)

static uint8_t const desc_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_TOTAL, 0, CONFIG_LEN, 0x00, 100),
    TUD_HID_INOUT_DESCRIPTOR(ITF_HID, 4, HID_ITF_PROTOCOL_NONE, sizeof(desc_hid_report), EP_HID_OUT,
                             EP_HID_IN, CFG_TUD_HID_EP_BUFSIZE, 5),
    TUD_CDC_DESCRIPTOR(ITF_CDC, 5, EP_CDC_NOTIF, 8, EP_CDC_OUT, EP_CDC_IN, 64),
};

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
  (void)index;
  return desc_configuration;
}

static char const *const strings[] = {
    NULL,                      // 0: language
    "docker-icloudpd",         // 1: manufacturer
    "Soft Security Key",       // 2: product
    NULL,                      // 3: serial (board id)
    "FIDO",                    // 4: HID interface
    "Soft Security Key link",  // 5: CDC interface
};

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
  (void)langid;
  static uint16_t desc[33];
  char serial[2 * PICO_UNIQUE_BOARD_ID_SIZE_BYTES + 1];
  const char *str;
  size_t count;

  if (index == 0) {
    desc[1] = 0x0409;
    count = 1;
  } else {
    if (index == 3) {
      pico_get_unique_board_id_string(serial, sizeof(serial));
      str = serial;
    } else if (index < sizeof(strings) / sizeof(strings[0])) {
      str = strings[index];
    } else {
      return NULL;
    }
    count = strlen(str);
    if (count > 32) count = 32;
    for (size_t i = 0; i < count; i++) desc[1 + i] = (uint16_t)str[i];
  }
  desc[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * count + 2));
  return desc;
}

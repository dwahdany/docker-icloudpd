// USB bridge for the software security key.
//
// The board enumerates as a FIDO HID security key and as a serial port. Every
// 64-byte HID report from the computer is copied to the serial port, and every
// 64 bytes read from the serial port are sent back as a HID report. The
// authenticator itself (and its private key) is the program on the other end
// of the serial port: scripts/softkey/bridge.py. Nothing secret is on the board.
#include <string.h>

#include "pico/stdlib.h"
#include "tusb.h"

#define PACKET 64
#define RING 256  // packets; one CTAP message is at most 129

static uint8_t ring[RING][PACKET];
static volatile uint16_t ring_head, ring_tail;  // head: next write, tail: next read

static uint8_t to_hid[PACKET];
static uint8_t to_hid_len;

// HID report from the computer (interrupt OUT endpoint or SET_REPORT).
void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t type,
                           uint8_t const *buffer, uint16_t size) {
  (void)itf;
  (void)report_id;
  (void)type;
  uint16_t next = (uint16_t)((ring_head + 1) % RING);
  if (next == ring_tail || size == 0) return;  // full: drop (cannot happen within one message)
  memset(ring[ring_head], 0, PACKET);
  memcpy(ring[ring_head], buffer, size > PACKET ? PACKET : size);
  ring_head = next;
}

uint16_t tud_hid_get_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t type,
                               uint8_t *buffer, uint16_t size) {
  (void)itf;
  (void)report_id;
  (void)type;
  (void)buffer;
  (void)size;
  return 0;
}

// The program on the serial side (re)connected: start from a clean packet boundary.
void tud_cdc_line_state_cb(uint8_t itf, bool dtr, bool rts) {
  (void)rts;
  if (dtr) {
    ring_tail = ring_head;
    to_hid_len = 0;
    tud_cdc_n_read_flush(itf);
  }
}

static void pump(void) {
  // computer -> authenticator
  while (ring_tail != ring_head && tud_cdc_connected() && tud_cdc_write_available() >= PACKET) {
    tud_cdc_write(ring[ring_tail], PACKET);
    ring_tail = (uint16_t)((ring_tail + 1) % RING);
    tud_cdc_write_flush();
  }
  // authenticator -> computer
  if (to_hid_len < PACKET && tud_cdc_available()) {
    to_hid_len += (uint8_t)tud_cdc_read(to_hid + to_hid_len, (uint32_t)(PACKET - to_hid_len));
  }
  if (to_hid_len == PACKET && tud_hid_ready()) {
    if (tud_hid_report(0, to_hid, PACKET)) to_hid_len = 0;
  }
}

int main(void) {
  tusb_init();
  while (true) {
    tud_task();
    pump();
  }
}

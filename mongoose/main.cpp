#include "mgos.h"

#include <Adafruit_SSD1306.h>

#include "client.h"
#include "ipmi.h"
#include "ipmi_mongoose.h"

static Adafruit_SSD1306 *display = nullptr;

#define FONT_HEIGHT1 8
#define FONT_HEIGHT2 16
#define FONT_HEIGHT3 24

// static bool boot_signal_sent = 0;

static void display_status(Adafruit_SSD1306 *d, const char *text) {
  d->setTextSize(1);

  // Blank the top line
  d->fillRect(0, 0, 128, 16, WHITE);
  d->setTextColor(BLACK, WHITE);
  d->setCursor(2, 3);
  d->printf("%s", text);
  d->display();
}

// static void display_text(Adafruit_SSD1306 *d, const char *s) {
//   // Clear the main display
//   d->fillRect(0, FONT_HEIGHT2, 128, 64, BLACK);

//   d->setTextSize(2);
//   d->setTextColor(WHITE);
//   d->setCursor(0, FONT_HEIGHT2 /* first row */);
//   d->printf("%s", s);
//   d->display();
// }

void foo(struct mg_connection *nc, int ev, void *ev_data, void *user_data) {
  LOG(LL_INFO, ("event %d", ev));
  (void)nc;
  (void)ev_data;
  (void)user_data;
}
static void ipmi() {
  uint8_t password[16] = {};
  strncpy((char *)password, "fancypants", 16);
  auto client = new IPMI::Client(password);

#if CS_PLATFORM == CS_P_UNIX || CS_PLATFORM == CS_P_WINDOWS
  struct mg_connect_opts opts = {.user_data = client};
  auto conn = mg_connect_opt(mgos_get_mgr(), "udp://pork-ipmi:623",
                             ipmi_client_connection_handler, opts);
#else
  // Mongoose OS has a different mg_connect and mg_connect_opt signature
  auto conn = mg_connect(mgos_get_mgr(), "udp://pork-ipmi:623",
                         ipmi_client_connection_handler, client);
#endif
  client->setConnection(conn);
  client->chassisControl(IPMI::ChassisControlCommand::PowerUp);
}

static void network_status_cb(int ev, void *evd, void *arg) {
  switch (ev) {
  case MGOS_NET_EV_DISCONNECTED:
    LOG(LL_INFO, ("%s", "Net disconnected"));
    break;
  case MGOS_NET_EV_CONNECTING:
    LOG(LL_INFO, ("%s", "Net connecting..."));
    break;
  case MGOS_NET_EV_CONNECTED:
    display_status(display, "Connected");
    break;
  case MGOS_NET_EV_IP_ACQUIRED:
    display_status(display, "Online.");
    LOG(LL_INFO, ("%s", "Online"));
    ipmi();

    break;
  }

  (void)evd;
  (void)arg;
}

enum mgos_app_init_result mgos_app_init(void) {
  mgos_event_add_group_handler(MGOS_EVENT_GRP_NET, network_status_cb, NULL);

  display =
      new Adafruit_SSD1306(4 /* RST GPIO */, Adafruit_SSD1306::RES_128_64);

  if (display != nullptr) {
    display->begin(SSD1306_SWITCHCAPVCC,
                   0x3C /* Check the ID on the display or use i2c scanning
                   */,
                   true /* reset */);
    display->display();
    display->fillScreen(BLACK);
    display_status(display, "Booting...");
  }

  return MGOS_APP_INIT_SUCCESS;
}
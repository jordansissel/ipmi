#include "mongoose.h"
#include "insist.h"
#include "ipmi.h"
#include "ipmi_mongoose.h"

#define GET_CHANNEL_AUTH_CAP "\x06\x00\xff\x07" \
  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18\xc8\x81\x04\x38" \
  "\x0e\x04\x31"

int main() {
  const auto client = new IPMI::Client;
  struct mg_mgr mgr;
  mg_mgr_init(&mgr, NULL);

  struct mg_connect_opts opts = {
    .user_data = client
  };

  mg_connect_opt(&mgr, "udp://pork-ipmi:623", ipmi_client_connection_handler, opts);

  client->chassisControl(IPMI::ChassisControlCommand::PowerUp);

  for (;;) {  // Start infinite event loop
    mg_mgr_poll(&mgr, 1000);
  }
  mg_mgr_free(&mgr);

}

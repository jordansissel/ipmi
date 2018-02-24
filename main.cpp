#include "client.h"
#include "insist.h"
#include "ipmi_mongoose.h"
#include "mongoose.h"

int main() {
  const auto client = new IPMI::Client;
  struct mg_mgr mgr;
  mg_mgr_init(&mgr, NULL);

  struct mg_connect_opts opts = {};
  opts.user_data = client;

  auto connection = mg_connect_opt(&mgr, "udp://pork-ipmi:623",
                                   ipmi_client_connection_handler, opts);
  client->setConnection(connection);

  client->chassisControl(IPMI::ChassisControlCommand::PowerUp);

  for (;;) { // Start infinite event loop
    mg_mgr_poll(&mgr, 1000);
  }
  mg_mgr_free(&mgr);

  return 0;
}

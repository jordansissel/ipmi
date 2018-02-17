#include "mgos.h"
#include "insist.h"
#include "ipmi.h"
#include "ipmi_mongoose.h"

void ipmi_client_connection_handler(struct mg_connection *nc, int ev, void *evdata, void *u) {

}

int main() {
  mgos_connect("udp://pork-ipmi:623", ipmi_client_connection_handler, NULL);

  client->chassisControl(IPMI::ChassisControlCommand::PowerUp);

  for (;;) {  // Start infinite event loop
    mg_mgr_poll(&mgr, 1000);
  }
  mg_mgr_free(&mgr);

}

#include "insist.h"
#include "ipmi_mongoose.h"
#include "mongoose.h"

#include <sys/socket.h>

#include "ipmi.h"

int main() {
  // const auto client = new IPMI::Client;
  // struct mg_mgr mgr;
  // mg_mgr_init(&mgr, NULL);

  // struct mg_connect_opts opts = {};
  // opts.user_data = client;

  // auto connection = mg_connect_opt(&mgr, "udp://pork-ipmi:623",
  //  ipmi_client_connection_handler, opts);
  // client->setConnection(connection);

  // client->chassisControl(IPMI::ChassisControlCommand::PowerUp);

  // for (;;) { // start infinite event loop
  //   mg_mgr_poll(&mgr, 1000);
  // }
  // mg_mgr_free(&mgr);

  int fd = socket(AF_INET, SOCK_DGRAM, 0);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(623); /* 623 == ipmi */

  auto host = gethostbyname("pork-ipmi");
  memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);

  struct mbuf buf;
  mbuf_init(&buf, 20);
  IPMI::getChannelAuthenticationCapabilities(buf);
  printf("Sending: \n");
  mg_hexdumpf(stdout, buf.buf, buf.len);
  sendto(fd, buf.buf, buf.len, 0, (const sockaddr *)&addr, sizeof(addr));
  mbuf_remove(&buf, buf.len);

  char recv[1500];
  int b = recvfrom(fd, recv, 1500, 0, NULL, NULL);
  mbuf_append(&buf, recv, b);

  printf("Received: \n");
  mg_hexdumpf(stdout, buf.buf, buf.len);

  IPMI::decodeChannelAuthenticationCapabilitiesResponse(buf);

  return 0;
}

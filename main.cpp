/*
    Copyright Jordan Sissel, 2018
    This file is part of jordansissel/ipmi.

    jordansissel/ipmi is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    jordansissel/ipmi is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with jordansissel/ipmi.  If not, see <http://www.gnu.org/licenses/>.
  */
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

  printf("1\n");
  int fd = socket(AF_INET, SOCK_DGRAM, 0);

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(623); /* 623 == ipmi */

  printf("2\n");
  struct addrinfo *host;
  int rc = getaddrinfo("pork-ipmi", NULL, NULL, &host);
  printf("getaddrinfo() %s\n", gai_strerror(rc));
  if (rc != 0) {
    return 1;
  }
  printf("3\n");
  memcpy(&addr.sin_addr, host->ai_addr, sizeof(addr.sin_addr));

  printf("4\n");
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

  IPMI::RMCP rmcp;
  IPMI::IPMB ipmb;
  IPMI::Session session;
  IPMI::GetChannelAuthenticationCapabilities::Response response;

  IPMI::decode(buf, rmcp, ipmb, session, response);

  if (response.completion_code != 0) {
    printf("ChannelAuthenticationCapabilities request failed.\n");
    return 1;
  }

  if (!response.hasMD5()) {
    printf("Remote claims no support for MD5 authcode. Cannot continue.\n");
    return 1;
  }

  IPMI::getSessionChallenge(buf);

  printf("Sending: \n");
  mg_hexdumpf(stdout, buf.buf, buf.len);
  sendto(fd, buf.buf, buf.len, 0, (const sockaddr *)&addr, sizeof(addr));
  mbuf_remove(&buf, buf.len);

  b = recvfrom(fd, recv, 1500, 0, NULL, NULL);
  mbuf_append(&buf, recv, b);

  printf("Received: \n");
  mg_hexdumpf(stdout, buf.buf, buf.len);

  IPMI::GetSessionChallenge::Response challengeResponse;
  IPMI::decode(buf, rmcp, ipmb, session, challengeResponse);

  // All future commands need an auth_code of:
  // md5(password + session id + data + sequence + password)
  // XXX: Add password.
  IPMI::activateSession(buf, challengeResponse.session_id,
                        challengeResponse.challenge);
  return 0;
}

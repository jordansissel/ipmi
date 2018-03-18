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

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "client.h"
#include "ipmi.h"

int mgos(int argc, char **argv) {
  if (argc != 3) {
    printf("Usage: %s <host> <password>\n", argv[0]);
    return 1;
  }

  const auto hostname = argv[1];
  uint8_t password[16] = {};
  strncpy((char *)password, argv[2], 16);

  auto client = IPMI::Client(password);

  struct mg_mgr mgr;
  mg_mgr_init(&mgr, NULL);

  struct mg_connect_opts opts = {.user_data = &client};

  char *address;
  asprintf(&address, "udp://%s:623", hostname);

  auto conn =
      mg_connect_opt(&mgr, address, ipmi_client_connection_handler, opts);
  client.setConnection(conn);

  client.chassisControl(IPMI::ChassisControlCommand::PowerUp);

  for (;;) { // Start infinite event loop
    mg_mgr_poll(&mgr, 1000);
  }
  mg_mgr_free(&mgr);
}

int posix(int argc, char **argv) {
  if (argc != 3) {
    printf("Usage: %s <host> <password>\n", argv[0]);
    return 1;
  }

  srandom(time(NULL));

  const auto hostname = argv[1];
  uint8_t password[16] = {};
  strncpy((char *)password, argv[2], 16);

  struct addrinfo *addresses, hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = 0;
  const int rc = getaddrinfo(hostname, "623", &hints, &addresses);
  insist_return(rc == 0, 1, "getaddrinfo() failed: %d: %s", rc,
                gai_strerror(rc));

  int fd = socket(addresses->ai_family, addresses->ai_socktype,
                  addresses->ai_protocol);
  insist_return(fd >= 0, 1, "socket() failed: %d: %s", errno, strerror(errno));

  char name[50];
  inet_ntop(addresses->ai_family,
            (addresses->ai_family == AF_INET)
                ? (const void *)&(
                      ((struct sockaddr_in *)addresses->ai_addr)->sin_addr)
                : (const void *)&(
                      ((struct sockaddr_in6 *)addresses->ai_addr)->sin6_addr),
            name, 50);
  printf("%s == %s\n", hostname, name);

  struct mbuf buf;
  mbuf_init(&buf, 20);

  // Send Get Channel Authentication Capabilities
  IPMI::getChannelAuthenticationCapabilities(buf);
  printf("Sending: \n");
  mg_hexdumpf(stdout, buf.buf, buf.len);
  sendto(fd, buf.buf, buf.len, 0, addresses->ai_addr, addresses->ai_addrlen);
  mbuf_remove(&buf, buf.len);

  // Receive Get Channel Authentication Capabilities Response
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

  // Send Get Session Challenge
  IPMI::getSessionChallenge(buf);

  printf("Sending: \n");
  mg_hexdumpf(stdout, buf.buf, buf.len);
  sendto(fd, buf.buf, buf.len, 0, addresses->ai_addr, addresses->ai_addrlen);
  mbuf_remove(&buf, buf.len);

  // Receive Get Session Challenge Response
  b = recvfrom(fd, recv, 1500, 0, NULL, NULL);
  printf("Before read len: %zd\n", buf.len);
  mbuf_append(&buf, recv, b);
  printf("After read len: %zd\n", buf.len);

  mg_hexdumpf(stdout, buf.buf, buf.len);

  IPMI::GetSessionChallenge::Response challengeResponse;
  IPMI::decode(buf, rmcp, ipmb, session, challengeResponse);

  // All future commands need an auth_code of:
  // md5(password + session id + data + sequence + password)
  // XXX: Add password.
  uint32_t sequence = (uint32_t)random();
  IPMI::activateSession(buf, password, sequence, challengeResponse.session_id,
                        challengeResponse.challenge);
  printf("! Sending: \n");
  mg_hexdumpf(stdout, buf.buf, buf.len);
  sendto(fd, buf.buf, buf.len, 0, addresses->ai_addr, addresses->ai_addrlen);
  mbuf_remove(&buf, buf.len);

  // Receive ActivateSession Response
  b = recvfrom(fd, recv, 1500, 0, NULL, NULL);
  mbuf_append(&buf, recv, b);

  printf("Received: \n");
  mg_hexdumpf(stdout, buf.buf, buf.len);

  IPMI::ActivateSession::Response activateResponse;
  IPMI::decode(buf, password, rmcp, ipmb, session, activateResponse);

  uint32_t session_id = activateResponse.session;
  sequence = activateResponse.sequence;

  // Send SetSessionPrivilege
  IPMI::setSessionPrivilege(buf, session_id, sequence, password,
                            IPMI::AuthenticationCapability::Administrator);
  sequence++;
  printf("!! Sending: \n");
  mg_hexdumpf(stdout, buf.buf, buf.len);
  sendto(fd, buf.buf, buf.len, 0, addresses->ai_addr, addresses->ai_addrlen);
  mbuf_remove(&buf, buf.len);

  // Receive SetSessionPrivilege response
  b = recvfrom(fd, recv, 1500, 0, NULL, NULL);
  mbuf_append(&buf, recv, b);

  printf("Received: \n");
  mg_hexdumpf(stdout, buf.buf, buf.len);
  IPMI::SetSessionPrivilege::Response privilegeResponse;
  IPMI::decode(buf, password, rmcp, ipmb, session, privilegeResponse);

  // Send Chassis Control
  IPMI::chassisControl(buf, challengeResponse.session_id, sequence, password,
                       IPMI::ChassisControlCommand::PowerUp);
  sequence++;
  printf("!! Sending: \n");
  mg_hexdumpf(stdout, buf.buf, buf.len);
  sendto(fd, buf.buf, buf.len, 0, addresses->ai_addr, addresses->ai_addrlen);

  // Receive Chassis Control response
  b = recvfrom(fd, recv, 1500, 0, NULL, NULL);
  mbuf_append(&buf, recv, b);

  printf("Received: \n");
  mg_hexdumpf(stdout, buf.buf, buf.len);

  return 0;
}
int main(int argc, char **argv) { return mgos(argc, argv); }
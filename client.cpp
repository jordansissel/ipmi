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
#include "client.h"

namespace IPMI {
static char unknown_buf[50];
static const char *stateToString(const ClientState s) {
  switch (s) {
  case ClientState::Initial:
    return "Initial";
  case ClientState::NeedChannelAuthenticationCapabilities:
    return "NeedChannelAuthenticationCapabilities";
  case ClientState::NeedSessionChallenge:
    return "NeedSessionChallenge";
  case ClientState::NeedActivateSession:
    return "NeedActivateSession";
  case ClientState::NeedSetSessionPrivilegeLevel:
    return "NeedSetSessionPrivilegeLevel";
  case ClientState::SessionReady:
    return "SessionReady";
  }

  sprintf(unknown_buf, "Unknown state: %d", (int)s);
  return unknown_buf;
}

void Client::send(ChassisControlCommand command) {
  printf("send() state = %s\n", stateToString(state));
  requestQueue.push_back(command);

  if (state == ClientState::Initial && connection != NULL) {
    begin();
  }
}

void Client::chassisControl(ChassisControlCommand command) {
  printf("State: %s\n", stateToString(state));
  send(command);
}

void Client::begin() {
  state = ClientState::NeedChannelAuthenticationCapabilities;
  printf("Begin... %s\n", stateToString(state));
  // Send the ChannelAuthenticationCapabilities packet
  struct rmcp rmcp = getChannelAuthenticationCapabilities(
      AuthenticationCapability::Administrator);
  mg_hexdumpf(stdout, &rmcp, 23);
  mg_send(connection, &rmcp, 23);
  ;
}

void Client::receivePacket(struct mbuf buf) {
  printf("receivePacket() state = %s\n", stateToString(state));
  struct mbuf test;
  mbuf_init(&test, 1000);

  switch (state) {
  case ClientState::Initial:
    begin();
    break;
  case ClientState::NeedChannelAuthenticationCapabilities:
    receive(buf);
    // If all is good, set state NeedSessionChallenge and send a
    // GetSessionChallenge request
    break;
  case ClientState::NeedSessionChallenge:
    receive(buf);
    // If all is good, set state NeedActivateSssion and send a
    // ActivateSssion request
    break;
  case ClientState::NeedActivateSession:
    // If all is good, set state NeedActivateSssion and send a
    // SetSessionPrivilegeLevel request
    break;
  case ClientState::NeedSetSessionPrivilegeLevel:
    // If all is good, set state SessionReady

    // After: Pop any command waiting in the queue and send it.
    break;
  case ClientState::SessionReady:
    // what now?
    // After: Pop any command waiting in the queue and send it.
    break;
  }
}

void Client::receive(struct mbuf buf) {
  struct rmcp *r = (struct rmcp *)buf.buf;
  printf("RECEIVED COMMAND: %02x\n", r->message.command);
  mg_hexdumpf(stdout, buf.buf, buf.len);
  printf(" ==>\n");

  switch (r->message.command) {
  case 0x38: /* GetChannelAuthenticationCapabilities */
    handle(r->message.parameters.getChannelAuthenticationCapabilities);
    break;
  case 0x39: /* GetSessionChallenge */
    handle(r->message.parameters.getSessionChallenge);
    break;
  default:
    printf("Unknown command: %02x\n", r->message.command);
  }
}

void Client::handle(const GetSessionChallenge &message) {
  if (message.response.completion_code != 0) {
    printf("GetSessionChallenge command failed: %d\n",
           message.response.completion_code);
    return;
  }

  printf("Temporary session id: %08x\n", message.response.session_id);
  printf("Challenge: ");
  mg_hexdumpf(stdout, message.response.challenge, 16);

  uint8_t password[16];
  memset(password, 0, 16);
  memcpy(password, getenv("IPMI_AUTH"), strlen(getenv("IPMI_AUTH")));

  if (state == ClientState::NeedSessionChallenge) {
    state = ClientState::NeedActivateSession;
    struct rmcp_with_auth packet = getActivateSession(
        password, message.response.challenge, message.response.session_id);
    mg_hexdumpf(stdout, &packet, 13 + 16 + 29 + 1);
    mg_send(connection, (const void *)&packet,
            13 + 16 + 29 + 1 /* XXX: compute this */);
  }
}

void Client::handle(const GetChannelAuthenticationCapabilities &message) {
  if (message.response.completion_code != 0) {
    printf("GetChannelAuthenticationCapabilities command failed: %d\n",
           message.response.completion_code);
    return;
  }

  if (!AUTH_TYPE_MD5(message.response.auth_type1)) {
    printf("Remote IPMI/BMC does not support MD5 authentication. Cannot "
           "continue.\n");
    return;
  }

  printf("getChannelAuthenticationCapabilities OK\n");
  if (state == ClientState::NeedChannelAuthenticationCapabilities) {
    state = ClientState::NeedSessionChallenge;
    struct rmcp packet = getSessionChallenge();
    mg_hexdumpf(stdout, &packet, 13 + 24 + 1);
    mg_send(connection, (const void *)&packet,
            13 + 24 + 1 /* XXX: compute this */);
  }
}

void Client::setConnection(mg_connection *c) {
  state = ClientState::Initial;
  connection = c;

  if (requestQueue.size() > 0) {
    begin();
  }
}
}; // namespace IPMI
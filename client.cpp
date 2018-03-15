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
#include <stdlib.h> // for random()

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
  IPMI::getChannelAuthenticationCapabilities(buffer);
  mg_send(connection, buffer.buf, buffer.len);
  mbuf_remove(&buffer, buffer.len);
}

void Client::receivePacket(struct mbuf payload) {
  IPMI::RMCP rmcp;
  IPMI::IPMB ipmb;
  IPMI::Session session;
  printf("receivePacket() state = %s\n", stateToString(state));

  switch (state) {
  case ClientState::Initial:
    printf("Invalid state? Received a packet when state=Initial?");
    break;
  case ClientState::NeedChannelAuthenticationCapabilities:
    receiveChannelAuthenticationCapabilities(payload);
    break;
  case ClientState::NeedSessionChallenge:
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

void Client::receiveChannelAuthenticationCapabilities(struct mbuf payload) {
  IPMI::RMCP rmcp;
  IPMI::IPMB ipmb;
  IPMI::Session session;
  IPMI::GetChannelAuthenticationCapabilities::Response response;

  IPMI::decode(payload, rmcp, ipmb, session, response);

  // If all is good, set state NeedSessionChallenge and send a
  // GetSessionChallenge request
  if (response.completion_code != 0) {
    printf("IPMI abort: ChannelAuthenticationCapabilities request failed.\n");
    return;
  }

  if (!response.hasMD5()) {
    printf("IPMI abort: Remote claims no support for MD5 authcode. Cannot "
           "continue.\n");
    return;
  }

  state = ClientState::NeedSessionChallenge;

  IPMI::getSessionChallenge(buffer);
  mg_send(connection, buffer.buf, buffer.len);
  mbuf_remove(&buffer, buffer.len);
}

void Client::receiveChallenge(struct mbuf payload) {
  IPMI::RMCP rmcp;
  IPMI::IPMB ipmb;
  IPMI::Session session;
  IPMI::GetSessionChallenge::Response response;

  IPMI::decode(payload, rmcp, ipmb, session, response);

  session_id = response.session_id;

  sequence = (uint32_t)random();

  state = ClientState::NeedActivateSession;

  IPMI::activateSession(buffer, password, sequence, session_id,
                        response.challenge);
  mg_send(connection, buffer.buf, buffer.len);
  mbuf_remove(&buffer, buffer.len);
}

void Client::setConnection(mg_connection *c) {
  state = ClientState::Initial;
  connection = c;

  if (requestQueue.size() > 0) {
    begin();
  }
}
}; // namespace IPMI
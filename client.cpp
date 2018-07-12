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

#if CS_PLATFORM == CS_P_UNIX
#include <stdlib.h> // for random()
#else
#include <limits.h>
#include <mgos_utils.h>

// Provide random() on platforms like ESP32
uint32_t random() { return (uint32_t)mgos_rand_range(0, INT_MAX); }
#endif

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
  case ClientState::NeedChassisControlResponse:
    return "NeedChassisControlResponse";
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

  Status status = Status::Success;
  switch (state) {
  case ClientState::Initial:
    printf("Invalid state? Received a packet when state=Initial?");
    break;
  case ClientState::NeedChannelAuthenticationCapabilities:
    status = receiveChannelAuthenticationCapabilities(payload);
    break;
  case ClientState::NeedSessionChallenge:
    status = receiveSessionChallenge(payload);
    break;
  case ClientState::NeedActivateSession:
    status = receiveActivateSession(payload);
    break;
  case ClientState::NeedSetSessionPrivilegeLevel:
    status = receiveSetSessionPrivilegeLevel(payload);
    break;
  case ClientState::SessionReady:
    // what now?
    // After: Pop any command waiting in the queue and send it.
    break;
  case ClientState::NeedChassisControlResponse:
    status = receiveChassisControl(payload);
  }

  if (status == Status::Failure) {
    if (failures < max_failures) {
      printf("IPMI request failed. Will retry.\n");
      failures++;
    } else {
      printf("IPMI failed to many times. Giving up. (Failures: %d)\n",
             failures);
    }
  }
}

Status Client::receiveChannelAuthenticationCapabilities(struct mbuf payload) {
  IPMI::RMCP rmcp;
  IPMI::IPMB ipmb;
  IPMI::Session session;
  IPMI::GetChannelAuthenticationCapabilities::Response response;

  auto status = IPMI::decode(payload, rmcp, ipmb, session, response);
  if (status == Status::Failure) {
    return status;
  }

  // If all is good, set state NeedSessionChallenge and send a
  // GetSessionChallenge request
  if (response.completion_code != 0) {
    printf("IPMI abort: ChannelAuthenticationCapabilities request failed.\n");
    return Status::Failure;
  }

  if (!response.hasMD5()) {
    printf("IPMI abort: Remote claims no support for MD5 authcode. Cannot "
           "continue.\n");
    return Status::Failure;
  }

  state = ClientState::NeedSessionChallenge;

  IPMI::getSessionChallenge(buffer);
  mg_send(connection, buffer.buf, buffer.len);
  mbuf_remove(&buffer, buffer.len);
  return Status::Success;
}

Status Client::receiveSessionChallenge(struct mbuf payload) {
  IPMI::RMCP rmcp;
  IPMI::IPMB ipmb;
  IPMI::Session session;
  IPMI::GetSessionChallenge::Response response;

  auto status = IPMI::decode(payload, rmcp, ipmb, session, response);
  if (status == Status::Failure) {
    return status;
  }

  session_id = response.session_id;

  sequence = (uint32_t)random();

  state = ClientState::NeedActivateSession;

  IPMI::activateSession(buffer, password, sequence, session_id,
                        response.challenge);
  mg_send(connection, buffer.buf, buffer.len);
  mbuf_remove(&buffer, buffer.len);
  return Status::Success;
}

Status Client::receiveActivateSession(struct mbuf payload) {
  IPMI::RMCP rmcp;
  IPMI::IPMB ipmb;
  IPMI::Session session;
  IPMI::ActivateSession::Response response;

  auto status = IPMI::decode(payload, password, rmcp, ipmb, session, response);
  if (status == Status::Failure) {
    return status;
  }

  session_id = response.session;

  sequence_out = response.sequence;

  state = ClientState::NeedSetSessionPrivilegeLevel;

  IPMI::setSessionPrivilege(buffer, session_id, sequence_out, password,
                            IPMI::AuthenticationCapability::Administrator);
  mg_hexdumpf(stdout, buffer.buf, buffer.len);
  mg_send(connection, buffer.buf, buffer.len);
  mbuf_remove(&buffer, buffer.len);

  sequence_out++;
  return Status::Success;
}

Status Client::receiveSetSessionPrivilegeLevel(struct mbuf payload) {
  IPMI::RMCP rmcp;
  IPMI::IPMB ipmb;
  IPMI::Session session;
  IPMI::SetSessionPrivilege::Response response;

  auto status = IPMI::decode(payload, password, rmcp, ipmb, session, response);
  if (status == Status::Failure) {
    return status;
  }

  // XXX: Verify the response has the requested privilege level

  state = ClientState::SessionReady;

  // Send Chassis Control?
  auto command = requestQueue.front();
  requestQueue.pop_front();
  IPMI::chassisControl(buffer, session_id, sequence_out, password, command);
  sequence_out++;
  mg_send(connection, buffer.buf, buffer.len);
  mbuf_remove(&buffer, buffer.len);

  state = ClientState::NeedChassisControlResponse;
  return Status::Success;
}

Status Client::receiveChassisControl(struct mbuf payload) {
  printf("Received ChassisControl response\n");
  mg_hexdumpf(stdout, payload.buf, payload.len);
  return Status::Success;
}

void Client::setConnection(mg_connection *c) {
  state = ClientState::Initial;
  connection = c;

  if (requestQueue.size() > 0) {
    begin();
  }
}
}; // namespace IPMI
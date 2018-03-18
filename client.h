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
#pragma once
#include "ipmi.h"
#include <list>

namespace IPMI {
enum class ClientState {
  Initial,
  NeedChannelAuthenticationCapabilities,
  NeedSessionChallenge,
  NeedActivateSession,
  NeedSetSessionPrivilegeLevel,
  SessionReady,
  NeedChassisControlResponse
};

class Client {
private:
  ClientState state = ClientState::Initial;
  std::list<ChassisControlCommand> requestQueue{};
  struct mbuf buffer;

  uint8_t password[16];
  uint32_t session_id;
  uint32_t sequence;
  uint32_t sequence_out;

  mg_connection *connection;

  void send(ChassisControlCommand);
  void receiveChannelAuthenticationCapabilities(struct mbuf payload);
  void receiveSessionChallenge(struct mbuf payload);
  void receiveActivateSession(struct mbuf payload);
  void receiveSetSessionPrivilegeLevel(struct mbuf payload);
  void receiveChassisControl(struct mbuf payload);
  void begin();

public:
  Client(uint8_t password[16]) : state{ClientState::Initial} {
    printf("Init: %d\n", (int)state);
    memcpy(this->password, password, 16);
    mbuf_init(&buffer, 30);
  }
  void chassisControl(ChassisControlCommand command);
  void receivePacket(struct mbuf buf);

  void setConnection(mg_connection *);
};
}; // namespace IPMI
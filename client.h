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

namespace IPMI {
enum class ClientState {
  Initial,
  NeedChannelAuthenticationCapabilities,
  NeedSessionChallenge,
  NeedActivateSession,
  NeedSetSessionPrivilegeLevel,
  SessionReady
};

class Client {
private:
  ClientState state = ClientState::Initial;
  std::list<ChassisControlCommand> requestQueue{};

  uint16_t authSupport;
  mg_connection *connection;

  void send(ChassisControlCommand);
  void receive(struct mbuf);
  void handle(const GetChannelAuthenticationCapabilities &);
  void handle(const GetSessionChallenge &);
  void begin();

public:
  Client() : state{ClientState::Initial} { printf("Init: %d\n", (int)state); }
  void chassisControl(ChassisControlCommand command);
  void receivePacket(struct mbuf buf);

  void setConnection(mg_connection *);
};
}; // namespace IPMI
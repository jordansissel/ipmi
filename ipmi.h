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
#include "mongoose.h"
#include <stdint.h>

namespace IPMI {
enum class AuthenticationCapability {
  Reserved = 0,
  Callback = 1,
  User = 2,
  Operator = 3,
  Administrator = 4,
  OEM = 5
};

enum class ChassisControlCommand {
  PowerDown = 0,
  PowerUp = 1,
  PowerCycle = 2,
  HardReset = 3,
  PulseDiagnosticInterrupt = 5,
  SoftShutdown = 5
};

class Serializable {
public:
  virtual void write(struct mbuf &out) const = 0;
  virtual void read(struct mbuf &out) = 0;
};

class Command : public Serializable {
public:
  virtual uint8_t length() const = 0;
};

class RMCP : public Serializable {
  uint8_t version;       /* Per spec: 0x06, ASF 2.0 */
  uint8_t reserved;      /* reserved by spec */
  uint8_t sequence;      /* rmcp sequence number */
  uint8_t message_class; /* the kind of message. "normal ipmi" is 0x07 */

public:
  RMCP() : version(0x06), reserved(0x00), sequence(0xff), message_class(0x07) {}
  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
};

class Session : public Serializable {
  uint8_t auth_type;
  uint32_t sequence;
  uint32_t id;
  uint8_t auth_code[16];
  uint8_t length;

public:
  Session(){};
  Session(uint8_t auth_type, uint32_t sequence, uint32_t id, uint8_t length)
      : auth_type(auth_type), sequence(sequence), id(id), length(length) {}
  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
};

const uint8_t IPMB_SIZE = 6;
const uint8_t CHECKSUM_SIZE = 1;
class IPMB : public Serializable {
  uint8_t target;
  uint8_t targetLun : 2;
  uint8_t netFn : 6;
  uint8_t checksum;

  uint8_t source;
  uint8_t sourceLun : 2;
  uint8_t sequence : 6;

public:
  uint8_t command;
  IPMB() {}
  IPMB(uint8_t netFn, uint8_t sequence, uint8_t command)
      : target(0x20), targetLun(0x0), netFn(netFn), checksum(-(0x20 + netFn)),
        source(0x81), sourceLun(0x0), sequence(sequence), command(command) {}
  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
};

namespace GetChannelAuthenticationCapabilities {
class Request : public Command {
  uint8_t channel;
  uint8_t privileges;

public:
  Request()
      : channel(0x0e),
        privileges((uint8_t)AuthenticationCapability::Administrator) {}
  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
  uint8_t length() const { return IPMB_SIZE + 2 + CHECKSUM_SIZE; }
};

class Response : public Command {
  uint8_t channel;
  uint8_t auth_type1;
  uint8_t auth_type2;
  uint8_t reserved;
  uint8_t oem1;
  uint8_t oem2;
  uint8_t oem3;
  uint8_t oem_aux;

public:
  uint8_t completion_code;
  Response() {}

  bool hasMD5() { return auth_type1 & (1 << 2); }

  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
  uint8_t length() const { return 9; };
};
} // namespace GetChannelAuthenticationCapabilities

namespace GetSessionChallenge {
class Request : public Command {
  uint8_t auth_type;
  uint8_t user[16];

public:
  Request() : auth_type(0x02 /* MD5 */), user("root\0\0\0\0\0\0\0\0\0\0\0") {}

  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
  uint8_t length() const {
    return 24 /* 6 (ipmb) + 17 (payload) + 1 (checksum) */;
  }
};

class Response : public Command {
public:
  uint32_t session_id;
  uint8_t challenge[16];
  Response() {}

  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
  uint8_t length() const { return 20; }
};
} // namespace GetSessionChallenge

namespace ActivateSession {
class Request : public Command {
  uint8_t auth_type;
  uint8_t privilege;
  uint8_t challenge[16];
  uint32_t sequence;

public:
  Request() : auth_type(0x02 /* MD5 */), privilege(0x04 /* Administrator */) {}
  Request(uint32_t sequence, uint8_t challenge[16])
      : auth_type(0x02 /* MD5 */), privilege(0x04 /* Administrator */),
        sequence(sequence) {
    memcpy(this->challenge, challenge, 16);
  }

  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
  uint8_t length() const { return 29; }
};
class Response : public Command {
  uint8_t auth_type;
  uint8_t privilege;

public:
  uint32_t session;
  uint32_t sequence;
  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
  uint8_t length() const { return 10; }
};

} // namespace ActivateSession

namespace SetSessionPrivilege {
class Request : public Command {
  uint8_t privilege;

public:
  Request(){};
  Request(uint8_t privilege) : privilege(privilege) {}

  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
  uint8_t length() const { return 8; }
};
class Response : public Command {
  uint8_t privilege;

public:
  Response(){};
  Response(uint8_t privilege) : privilege(privilege) {}
  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
  uint8_t length() const { return 8; }
};
} // namespace SetSessionPrivilege

namespace ChassisControl {
class Request : Command {
  uint8_t command;

public:
  Request() {}
  Request(ChassisControlCommand command) : command((uint8_t)command) {}
  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
  uint8_t length() const { return 8; }
};
class Response : Command {
public:
  Response() {}
  void write(struct mbuf &out) const;
  void read(struct mbuf &in);
  uint8_t length() const { return 7; }
};
} // namespace ChassisControl

void getChannelAuthenticationCapabilities(struct mbuf &buf);
void decode(struct mbuf &buf, RMCP &rmcp, IPMB &ipmb, Session &session,
            GetChannelAuthenticationCapabilities::Response &response);
void getSessionChallenge(struct mbuf &buf);
void decode(struct mbuf &buf, RMCP &rmcp, IPMB &ipmb, Session &session,
            GetSessionChallenge::Response &response);

void activateSession(struct mbuf &buf, uint8_t password[16], uint32_t sequence,
                     uint32_t session_id, uint8_t challenge[16]);
void decode(struct mbuf &buf, const uint8_t password[16], RMCP &rmcp,
            IPMB &ipmb, Session &session, ActivateSession::Response &response);

void setSessionPrivilege(struct mbuf &buf, uint32_t session, uint32_t sequence,
                         uint8_t password[16],
                         IPMI::AuthenticationCapability privilege);
void decode(struct mbuf &buf, const uint8_t password[16], RMCP &rmcp,
            IPMB &ipmb, Session &session,
            SetSessionPrivilege::Response &response);

void chassisControl(struct mbuf &buf, uint32_t session, uint32_t sequence,
                    uint8_t password[16], ChassisControlCommand command);

} // namespace IPMI
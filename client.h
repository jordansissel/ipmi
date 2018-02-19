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

    struct details {
      
    };
    uint16_t authSupport;
    mg_connection *connection;

    void send(ChassisControlCommand);
    void receive(struct mbuf);
    void handle(const GetChannelAuthenticationCapabilities&);
    void handle(const GetSessionChallenge&);
    void begin();

  public:

    Client() : state{ClientState::Initial} {
      printf("Init: %d\n", (int) state);

    }
    void chassisControl(ChassisControlCommand command);
    void receivePacket(struct mbuf buf);

    void setConnection(mg_connection *);
  };
};